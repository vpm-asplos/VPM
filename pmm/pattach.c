#include <linux/syscalls.h>
#include <linux/huge_mm.h>
#include <linux/cred.h>
#include "pmm.h"
 
#define PHEAP_CREATE 1
#define PHEAP_SHARE 2

int preattach(void);

// Attach, used by the execv syscall
int preattach(void) {
  unsigned long oldpbrk = MIN_PBRK;
  unsigned long region_len = 0;
  struct vm_area_struct* target_vma = NULL;
  LIST_HEAD(uf);
  
  if(current->mm->pstore == NULL) {
    panic("[PMMEXEC] Error: you are calling preattach without attaching a pstore.");
  }
#ifdef PHUGEPAGE
  region_len = current->mm->pstore->cnt * HPAGE_PMD_SIZE;
#else
  region_len = current->mm->pstore->cnt * PAGE_SIZE;
#endif
  if(down_write_killable(&current->mm->mmap_sem)) {
    return -EINTR;
  }
  if(do_pbrk(current->mm, oldpbrk, region_len, &uf, &target_vma) < 0) {
    up_write(&current->mm->mmap_sem);
    return -ENOMEM;
  }
  up_write(&current->mm->mmap_sem);
  mm_populate(oldpbrk, region_len);
  return 0;
}

/*
 * guid: kernel string
 * If flag == PHEAP_CREATE
 * Else if flag == PHEAP_SHARE: attach an existing pheap
 */
SYSCALL_DEFINE3(pattach, const __user char *, guid, size_t, len, unsigned long, flag) {
  // Step 1: copy id in
  unsigned long ret = 0;
  char pmmid[PMMID_LEN_LIMIT] = {0};
  int i = 0;
  int check = -2;
  
  if(len > PMMID_LEN_LIMIT-1) {
    return -EINVAL;
  }
  ret = copy_from_user(pmmid, guid, len);
  pmmid[len] = '\0'; // add trailing '\0'
  if(ret) {
    return -EFAULT;
  }
  check = pmm_check_id_conflict(pmmid);

  if(check == -2) {
    printk("Panic! The check val shouldn't be -2. It can be either -1 or other values > 0");
    return -EINVAL;
  }
  if(flag == PHEAP_CREATE) {
    /*********** CREATE **********/
    struct pmm_store* cur_store;
    struct pmm_owner* powner;
    const struct cred *cred = current_cred();
    // create a new pregion for this
    if(check != -1) {
      /* printk("Now attaching ID: %s, but there is an ID conflict, return.", pmmid); */
      return -EINVAL;
    }
    if(current->mm->pstore != NULL) {
      /* printk("You must detach an existing pstore %s before creating a new one.", */
      /* 		      current->mm->pstore->pmmid); */
      return -EINVAL;
    }
    // printk("Now creating non-existing ID %s for pid: %lu", pmmid, current->pid);
    cur_store = &pdb.stores[pdb.store_cnt];
    /* Set initial pbrk and page count to zero */
    cur_store->cnt = 0;
    // copy pmmid to cur_store.pmmid
    for(i = 0; i < len; i ++) {
      cur_store->pmmid[i] = pmmid[i];
    }
    cur_store->pmmid[len] = '\0'; // trailing '\0'
    // set euid, egid and default permission
    cur_store->euid = cred->euid.val;
    cur_store->egid = cred->egid.val;
    cur_store->perm = DEFAULT_PERMISSION;
    // Init list head
    INIT_LIST_HEAD(&cur_store->head);
    /* Insert pstore into mm and pdb */
    current->mm->pstore = cur_store;
    pdb.store_cnt += 1;
    /* Add current process into the owner list */
    pmm_insert_pid_list(cur_store, current->pid);
    powner = pmm_get_owner_from_pid(cur_store, current->pid);
    powner->pbrk_start = MIN_PBRK;
    current->mm->pstore->pbrk = MIN_PBRK;
    return ret;
  } else if(flag  == PHEAP_SHARE) {
    /*********** ATTACH **********/
    unsigned long oldpbrk = MIN_PBRK;
    unsigned long region_len = 0;
    struct pmm_owner* owner = NULL;
    struct vm_area_struct *target_vma = NULL;
    LIST_HEAD(uf);
    if(check == -1) {
      printk("Error when attaching ID: %s, but there is no existing store with this ID, return.", pmmid);
      return -EINVAL;
    }
    if(current->mm->pstore != NULL) {
      printk("Error when attaching ID: %s, please detach current pheap %s first.", pmmid, current->mm->pstore->pmmid);
      return -EINVAL;
    }
    
    /* Permission checking: if has both read and write, then attach, else refuse to attach. */
    /* TODO: implement mprotect RO mapping */
    if(!permission_rw(pdb.stores[check].euid, pdb.stores[check].egid,
		      pdb.stores[check].perm)) {
	    printk("Attach failed because of no permission! permission: %x",
			    pdb.stores[check].perm);
      return -EACCES;
    }
    
    /* Load vma into the kernel: get pbrk, then call do_pbrk() */
    // PTE: 9, POFFSET: 12, PMD: 9, HPAGE_PMD_SIZE == 1 << HPAGE_PMD_SHIFT == 1 << 21
#ifdef PHUGEPAGE
    region_len = pdb.stores[check].cnt * HPAGE_PMD_SIZE;
#else
    region_len = pdb.stores[check].cnt * PAGE_SIZE;
#endif
    
    if(down_write_killable(&current->mm->mmap_sem)) {
      return -EINTR;
    }
    if(do_pbrk(current->mm, oldpbrk, region_len, &uf, &target_vma) < 0) {
      up_write(&current->mm->mmap_sem);
      printk("Attach failed because of no memory available.");
      return -ENOMEM;
    }
    /* populate. No need to record, because it is already in the pstore */
    current->mm->pstore = &pdb.stores[check];
    up_write(&current->mm->mmap_sem);
    mm_populate(oldpbrk, region_len);
    // Change owner list, don't hold mmap sem
    pmm_insert_pid_list(current->mm->pstore, current->pid);
    owner = pmm_get_owner_from_pid(current->mm->pstore, current->pid);
    owner->pbrk_start = MIN_PBRK;
    return ret;
  }
  return ret;
}

SYSCALL_DEFINE0(pdetach) {
  /* Unload vma from the kernel, resembles punmap code */
  unsigned long start = MIN_PBRK;
  unsigned long cur_pbrk = 0;
  unsigned long len = 0;
  struct pmm_owner *powner = NULL; 

  if(current->mm->pstore == NULL) {
    printk("Error: you are calling detach without attaching a pstore.");
    return -EINVAL;
  }
  powner = pmm_get_owner_from_pid(current->mm->pstore, current->pid);
  if(powner == NULL) {
    printk("Error: you are calling on a non-attached process.");
    return -EINVAL;
  }
  start = powner->pbrk_start;
  cur_pbrk = current->mm->pstore->pbrk;
  len = (cur_pbrk - start);
  vm_munmap(start, len);
  pmm_delete_pid_from_list(current->mm->pstore, current->pid);
  current->mm->pstore = NULL;
  return 0;
}

SYSCALL_DEFINE1(pchmod, unsigned long, mode) {
  const struct cred *cred = current_cred();
  if(current == NULL || current->mm == NULL || current->mm->pstore == NULL) {
    return -EINVAL;
  }
  // Only root and the pheap owner can change the permission
  if(cred->euid.val == current->mm->pstore->euid ||
     cred->euid.val == 0) {
    current->mm->pstore->perm = mode;
    return 0;
  } else {
    return -EACCES;
  }
}
