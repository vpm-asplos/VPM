#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "pmm.h"

#define BUFSIZE 255

static spinlock_t plock = __SPIN_LOCK_UNLOCKED();

static void print_list(const char* msg, struct pmm_store* pstore, pid_t pid) {
  struct list_head *ptr = NULL;
  struct pmm_owner *item = NULL;
  char str[BUFSIZE];
  memset(str, 0, BUFSIZE);
  list_for_each(ptr, &pstore->head) {
    item = list_entry(ptr, struct pmm_owner, olist);
    sprintf(str + strlen(str), " -> %d", item->pid);
  }
  if(strlen(str) == 0) {
    printk("%s, pid %d: List empty!\n", msg, pid);
  } else {
    printk("%s, pid %d: %s\n", msg, pid, str);
  }
}

int permission_rw(unsigned long euid, unsigned long egid, unsigned long perm) {
  const struct cred *cred = current_cred();
  if(euid == cred->euid.val) { // same user
    if(((perm >> 8) & 0x0f) >= 0x6) {
      return 1; // owner has both r and w
    }
  } else if(egid == cred->egid.val) { // same group
    if(((perm >> 4) & 0x0f) >= 0x6) {
      return 1; // owner has both r and w
    }
  } else { // others
    if((perm & 0x0f) >= 0x6) {
      return 1; // owner has both r and w
    }
  }
  return 0;
}

struct pmm_owner* pmm_get_owner_from_pid(struct pmm_store* pstore, pid_t pid) {
  struct list_head *node = NULL;
  struct pmm_owner *pid_owner = NULL;
  struct pmm_owner *retval = NULL;
  if(pstore == NULL) return NULL;
  if(spin_is_locked(&plock)) {
	  printk("[Error] pmm_get_owner: is already locked!");
	  return NULL;
  }
  spin_lock(&plock);
  list_for_each(node, &pstore->head) {
    pid_owner = list_entry(node, struct pmm_owner, olist);
    if(pid_owner->pid == pid) {
      retval = pid_owner;
    }
  }
  spin_unlock(&plock);
  return retval;
}

void pmm_delete_pid_from_list(struct pmm_store* pstore, pid_t pid) {
  struct pmm_owner *todel = NULL;
  struct pmm_owner *second_member = NULL;
  struct list_head *node = NULL;
  struct list_head *q = NULL;

  int cnt = 0;
  if (pstore == NULL) { return; }
  if (spin_is_locked(&plock)) {
	  printk("Error!!! delete_pid_from_list: already locked!");
	  return;
  }
  spin_lock(&plock);
  print_list("[Delete] Before", pstore, pid);
  list_for_each_safe(node, q, &pstore->head) {
    todel = list_entry(node, struct pmm_owner, olist);
    // printk("[IN DEL] Now iterating: pid == %d, to_del pid =%d", todel->pid, pid);
    if(todel->pid == pid) {
      list_del(node);
      kfree(todel);
    }
  }
  print_list("[Delete] After", pstore, pid);
  spin_unlock(&plock);
  return;
}

void pmm_insert_pid_list(struct pmm_store* pstore, pid_t pid) {
  struct pmm_owner *newowner;
  if(spin_is_locked(&plock)) {
    printk("Error! insert_pid: already locked!!!");
    return;
  }
  spin_lock(&plock);
  print_list("[Insert] Before", pstore, pid);
  newowner = kmalloc(sizeof(struct pmm_owner), GFP_KERNEL);
  newowner->pid = pid;
  INIT_LIST_HEAD(&newowner->olist);
  list_add_tail(&newowner->olist, &pstore->head);
  print_list("[Insert] After", pstore, pid);
  spin_unlock(&plock);
}

int pmm_check_id_conflict(const char* pmmid) {
    int i = 0;
    for(i = 0; i < pdb.store_cnt; i ++) {
        char* existing_pmmid = pdb.stores[i].pmmid;
        if(strcmp(existing_pmmid, pmmid) == 0) {
            // there exists the pmm region with the same ID
            return i;
        }
    }
    // pmm region with the same id does not exist
    return -1;
}

// use the same tracking scheme as __get_user_pages() in mm/gup.c
unsigned long pmm_get_ptn_addr(struct vm_area_struct *vma,
			      unsigned long start, unsigned int gup_flags,
			      unsigned int *page_mask) {
  struct page* page_info = follow_page_mask(vma, start, gup_flags, page_mask);
  unsigned long pfn = page_to_pfn(page_info);
  // in the hugepage, page_frame_addr should be zero for last 21 bits, for the offset.
  return pfn;
} 
