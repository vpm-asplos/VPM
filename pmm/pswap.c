/*
 * pmm/pswap.c
 * Implementation of the pswap system call
 */
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/huge_mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <linux/stringify.h>
#include <../arch/x86/include/asm/alternative.h>
#include "pmm.h"

#define MAX_PSWAP_SIZE 100001

// Huge HPAGE_SIZE: 0x200000 (2M)
// Normal PAGE_SIZE: 0x1000 (4K)
#ifdef PHUGEPAGE
static int swap_hugepage_range(struct mm_struct* mm,
                               unsigned long start_addrs[],
                               unsigned long dest_addrs[],
                               unsigned long nrpages) {
    // Huge page table level
    pte_t *sptep;
    pte_t *tptep;
    pte_t temp;
    unsigned long i;
    struct vm_area_struct *vma;

    vma = find_vma(mm, start_addrs[0]); 
    for (i = 0; i < nrpages; i++) {
        unsigned long paddr;
        // get ptep from VA
        sptep = huge_pte_offset(mm, start_addrs[i], HPAGE_SIZE);
        tptep = huge_pte_offset(mm, dest_addrs[i], HPAGE_SIZE);
        if (!sptep || !tptep) {
            goto out;
        }
        // Now the magic starts
        temp = (*sptep);
        (*sptep) = (*tptep);
        (*tptep) = temp;
        flush_tlb_page(vma, start_addrs[i]);
        flush_tlb_page(vma, dest_addrs[i]);
    } // for each page
    return 0;
out:
    return -1;
}
#else
static pte_t* get_ptep(unsigned long addr, struct mm_struct *mm) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    pgd = pgd_offset(mm, addr);
    if (!pgd_present(*pgd)) {
        return NULL;
    }
    p4d = p4d_offset(pgd, addr);
    if (!p4d_present(*p4d)) {
        return NULL;
    }
    pud = pud_offset(p4d, addr);
    if (!pud_present(*pud)) {
        return NULL;
    }
    pmd = pmd_offset(pud, addr);
    if (!pmd_present(*pmd)) {
        return NULL;
    }
    ptep = pte_offset_map(pmd, addr);
    if (!ptep) {
      return NULL;
    } else {
        return ptep;
    }
}
static int swap_page_range(struct mm_struct *mm, unsigned long start_addrs[], 
                            unsigned long dest_addrs[],
                            unsigned long nrpages) {
    unsigned long i;
    struct vm_area_struct *vma;

    vma = find_vma(mm, start_addrs[0]);
    for (i = 0; i < nrpages; i ++) {
        pte_t *sptep;
        pte_t *tptep;
        pte_t temp;
        // get pointer to pte from the address, and swap them
        sptep = get_ptep(start_addrs[i], mm);
        tptep = get_ptep(dest_addrs[i], mm);
        if (!sptep || !tptep) {
            goto out;
        }
        temp = (*sptep);
        (*sptep) = (*tptep);
        (*tptep) = temp;
        // Don't forget to unmap ptep since they are mapped in get_ptep()
        pte_unmap(sptep);
        pte_unmap(tptep);
        flush_cache_range(vma, start_addrs[i], start_addrs[i]+PAGE_SIZE);
        flush_tlb_page(vma, start_addrs[i]);
        flush_cache_range(vma, dest_addrs[i], dest_addrs[i]+PAGE_SIZE);
        flush_tlb_page(vma, dest_addrs[i]);
    }
    return 0;
out:
    return -1;
}
#endif

// Read an array of addresses from user space ...
SYSCALL_DEFINE3(pswap, unsigned long, start, unsigned long, dest, unsigned long, nrpgs) {
    struct mm_struct *mm;
    struct pmm_owner *current_owner = NULL;
    const struct cred *c;
    unsigned long* start_addrs, *dest_addrs;
    unsigned long i = 0, j = 0;
    unsigned long res;
    int ret = 0;
    // Atomically swap the addresses in pstore
    // =============== WAL start ================
    unsigned long finished = 0; // flag
    unsigned long nrpages = nrpgs; // number of pages
    clwb(&nrpages);
    unsigned long *starts;
    unsigned long *dests;
    // =============== WAL end ==================

    if(!nrpgs) { // nothing to swap
        return 0;
    }
    
    mm = current->mm;
    // Sanity checks
    if (mm->pstore == NULL) {
        return -EINVAL;
    }
    current_owner = pmm_get_owner_from_pid(mm->pstore, current->pid);
    if(current_owner == NULL) {
         printk("This process is trying to pbrk a pheap it does not attach.\n");
        return -EINVAL;
    }
    // Check if current user has the permission to change the break.
    // If the user has read and write permission to the pheap, then she can change the break.
    c = current_cred();
    if (!permission_rw(c->euid.val, c->egid.val, mm->pstore->perm)) {
        return -EINVAL; 
    }
    
    if(nrpgs >= MAX_PSWAP_SIZE) {
        printk("We limit the %lu pages to swap in 1 transaction.\n", MAX_PSWAP_SIZE);
        return -EINVAL;
    }

    dests = kmalloc_array(nrpgs, sizeof(unsigned long), GFP_KERNEL);
    starts = kmalloc_array(nrpgs, sizeof(unsigned long), GFP_KERNEL);
    start_addrs = kmalloc_array(nrpgs, sizeof(unsigned long), GFP_KERNEL);
    dest_addrs = kmalloc_array(nrpgs, sizeof(unsigned long), GFP_KERNEL);

    // copy the parameters to the kernel
    res = copy_from_user((void*)start_addrs, (void*)start, nrpgs * sizeof(void*));
    if(res) {
        printk("Failed to copy start data from user!\n");
        return -EINVAL;
    }
    res = copy_from_user((void*)dest_addrs, (void*)dest, nrpgs * sizeof(void*));
    if(res) {
        printk("Faild to copy dest data from user!\n");
        return -EINVAL;
    }
    // check address are valid
#ifdef PHUGEPAGE
    for(i = 0; i < nrpgs; i ++) {
        if(start_addrs[i] % HPAGE_SIZE != 0) {
            return -EINVAL;
        }
        if(dest_addrs[i] % HPAGE_SIZE != 0) {
            return -EINVAL;
        }
    }
#else
    for(i = 0; i < nrpgs; i ++) {
        if(start_addrs[i] % PAGE_SIZE != 0) {
            return -EINVAL;
        }
        if(dest_addrs[i] % PAGE_SIZE != 0) {
            return -EINVAL;
        }
    }
#endif
    // Overlapping check
    /*
    for(i = 0; i < nrpgs; i ++) {
        for(j = 0; j < nrpgs; j ++) {
            if(start_addrs[i] == dest_addrs[j]) {
                printk("The addresses passed in are overlapping! %p\n", start_addrs[i]);
                return -EINVAL;
            }
        }
    }*/
    // Lock mmap semaphore
    if (down_write_killable(&mm->mmap_sem)) {
        return -EINTR;
    }

    // Step 1: Undo journal: copy the original data to the WAL file
    for (i = 0; i < nrpgs; i ++) {
#ifdef PHUGEPAGE
        unsigned long startid = (start_addrs[i] - current_owner->pbrk_start) / HPAGE_SIZE;
        unsigned long destid = (dest_addrs[i] - current_owner->pbrk_start) / HPAGE_SIZE;
        starts[i] = startid;
        dests[i] = destid;
#else
        unsigned long startid = (start_addrs[i] - current_owner->pbrk_start) / PAGE_SIZE;
        unsigned long destid = (dest_addrs[i] - current_owner->pbrk_start) / PAGE_SIZE;
        starts[i] = startid;
        dests[i] = destid;
#endif
        clwb(&starts[i]);
        clwb(&dests[i]);
    }
    __asm__ __volatile__("sfence\n"::);
    finished = 1;
    clwb(&finished);
    __asm__ __volatile__("sfence\n"::);
    // Step 2: copy is done, flush the page, and set the flag
    // Step 3: flag set is done, modify the pheap structure
    for (i = 0; i < nrpages; i++) {
        unsigned long temp = mm->pstore->pages[starts[i]].paddr;
        mm->pstore->pages[starts[i]].paddr = mm->pstore->pages[dests[i]].paddr;
        mm->pstore->pages[dests[i]].paddr = temp;
    }
    // free the WAL
    finished = 0;
    clwb(&finished);
    kfree(starts);
    kfree(dests);
    kfree(start_addrs);
    kfree(dest_addrs);
#ifdef PHUGEPAGE
    ret = swap_hugepage_range(mm, start_addrs, dest_addrs, nrpages);
#else
    ret = swap_page_range(mm, start_addrs, dest_addrs, nrpages);
    if (ret) {
        printk("return value: %lu \n", ret);
    }
#endif
    // Unlock the mmap semaphore
    up_write(&mm->mmap_sem);
    return ret;
}
