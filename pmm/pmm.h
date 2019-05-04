/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/seqlock.h>

#define MIN_PBRK 0x2a0002000000UL

// Stack top: 0x7fff ffff f000
// Heap bottom: 0x02000000
// p-heap size: 16TB = 2^44
// 8 p-heaps 

#define PMM_COUNT_LIMIT 16
// Length limit of PMM name
#define PMMID_LEN_LIMIT 256
// 0rw- 0r-- 0r-- 644 is the default
#define DEFAULT_PERMISSION 0x644
// By default we don't use hugepage
// #define PHUGEPAGE 0
#ifdef PHUGEPAGE
// MAX 2048 pages, 2M page
// Max 4G space
#define MAX_PMM_SIZE 2048
#else
// 4K Page, MAX 2^19 
// MAX 2G space
#define MAX_PMM_SIZE (524288)
#endif

// helper functions
struct pmm_owner* pmm_get_owner_from_pid(struct pmm_store* pstore, pid_t pid);
void pmm_delete_pid_from_list(struct pmm_store* pstore, pid_t pid);
pid_t pmm_get_head_owner(struct pmm_store* pstore);
void pmm_insert_pid_list(struct pmm_store* pstore, pid_t pid);
void extend_process_pbrk(struct task_struct *task, unsigned long oldpbrk,
                         unsigned long newpbrk);
int pmm_check_id_conflict(const char* pmmid);
int permission_rw(unsigned long euid, unsigned long egid, unsigned long perm);
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags); 

unsigned long pmm_get_ptn_addr(struct vm_area_struct *vma,
			      unsigned long start, unsigned int gup_flags,
			      unsigned int *page_mask);
int pmm_nonempty(void);
int do_pbrk(struct mm_struct *mm, unsigned long addr, unsigned long request, struct list_head* uf, struct vm_area_struct **target_vma);

// Store: a list of physical pages
// Each physical page: attach a struct, which pmm it belongs to
struct pmm_owner {
    pid_t pid;
    unsigned long pbrk_start; // to support address randomization
    struct list_head olist;
};

struct pmm_page {
    unsigned long euid;
    unsigned long egid;
    unsigned long perm;
    unsigned long paddr;
};

struct pmm_store {
    /* Name of the pheap */
    char pmmid[PMMID_LEN_LIMIT];
    /* the number of pmm pages in this pheap */
    int cnt;
    /* Each PMM page has its own physical addr, euid, egid, and permission mode */
    struct pmm_page pages[MAX_PMM_SIZE];
    /* pbrk value is not necessary, but is maintained */
    unsigned long pbrk; 
    /* head to the linked list that contains the attachers of this pheap */
    struct list_head head; 
    /* Concurrency: spinlock of modifying this pheap */
    spinlock_t plock;
    /* Permission mode of modifying this pheap */
    unsigned long euid;
    unsigned long egid;
    unsigned long perm;
};

// Overall pmm database in kernel
struct pmm_database {
  struct pmm_store stores[PMM_COUNT_LIMIT];
  int store_cnt;
};

extern struct pmm_database pdb;
