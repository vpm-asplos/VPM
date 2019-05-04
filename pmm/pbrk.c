/*
 * pmm/pbrk.c
 *
 *
 */
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/huge_mm.h>
#include <linux/mman.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/page-flags.h>
#include "pmm.h"



static inline int mlock_future_check(struct mm_struct *mm, unsigned long flags, unsigned long len);
static int find_vma_links(struct mm_struct *mm, unsigned long addr, unsigned long end, struct vm_area_struct **pprev, struct rb_node ***rb_link, struct rb_node **rb_parent);
static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma, struct vm_area_struct *prev, struct rb_node **rb_link, struct rb_node *rb_parent);
static void insert_pstore(struct mm_struct *mm, unsigned long paddr, unsigned long vaddr, unsigned long perm);
static int foreign_mm_populate(struct task_struct *tsk,
				struct mm_struct *mm, unsigned long start, unsigned long len);

struct pmm_database pdb;

SYSCALL_DEFINE2(pbrk, unsigned long, pbrk, unsigned long, perm)
{
  unsigned long retval;
  unsigned long newpbrk, oldpbrk;
  unsigned long min_pbrk;
  bool populate;
  struct mm_struct *mm = current->mm;
  struct vm_area_struct *next;
  struct vm_area_struct *target_vma = NULL;
  LIST_HEAD(uf);
  // for notifying other processes
  struct list_head *node = NULL;
  struct pmm_owner *current_owner = NULL;
  struct pmm_owner *pid_owner = NULL;
  const struct cred *c = NULL;
  
  if(mm->pstore == NULL) {
    // printk("There is no pstore attached! Now returning from pbrk.");
    return -EINVAL;
  }
  
  current_owner = pmm_get_owner_from_pid(mm->pstore, current->pid);
  if(current_owner == NULL) {
    // printk("This process is trying to pbrk a pheap it does not attach.");
    return -EINVAL;
  }

  // Check if current user has the permission to change the break.
  // If the user has read and write permission to the pheap, then she can change the break.
  c = current_cred();
  if (!permission_rw(c->euid.val, c->egid.val, mm->pstore->perm)) {
      return -EINVAL; 
  }

  // Setup the permission for the new memory pages. 0 means DEFAULT_PERMISSION
  if (perm == 0) {
      perm = DEFAULT_PERMISSION;
  }

  /* Lock mm mmap semaphore */
  if(down_write_killable(&mm->mmap_sem)) {
    return -EINTR;
  }
  min_pbrk = current_owner->pbrk_start;
  if(pbrk < min_pbrk) {
    goto out;
  }
  
  /* No need to check rlimit, skip */
#ifdef PHUGEPAGE  
  newpbrk = ALIGN(pbrk, HPAGE_SIZE);
  oldpbrk = ALIGN(mm->pstore->pbrk, HPAGE_SIZE);
  if(oldpbrk == newpbrk) {
    goto set_pbrk;
  }
#else
  newpbrk = ALIGN(pbrk, PAGE_SIZE);
  oldpbrk = PAGE_ALIGN(mm->pstore->pbrk);
  if (oldpbrk == newpbrk) {
      goto set_pbrk;
  }
#endif
  
  /* Always allow shrinking pbrk. */
  if(pbrk <= mm->pstore->pbrk) {
    /* TODO: shrink the region between oldbrk and new_brk */
    /* If unmap fails, goto out. TODO: for now we don't change */
    /* goto set_pbrk;*/
    goto out;
  }
  
  /* Now deal with increasing pbrk. */
  /* Check against existing mmap mappings. */
  next = find_vma(mm, oldpbrk);
#ifdef PHUGEPAGE
  if(next && newpbrk + HPAGE_SIZE > vm_start_gap(next)) {
    goto out;
  }
#else
   if(next && newpbrk + PAGE_SIZE > vm_start_gap(next)) {
    goto out;
  }
#endif
  
  if(do_pbrk(current->mm, oldpbrk, newpbrk - oldpbrk, &uf, &target_vma) < 0) {
    goto out; /* do_pbrk fails */
  }
  
set_pbrk:
  // if the break increases and def_flags 
  populate = (newpbrk > oldpbrk) && (mm->def_flags && VM_LOCKED) != 0;
  up_write(&mm->mmap_sem);
  // By default we prefault all pages.
  // Setup the page permissions  
  populate = 1;
  if (populate) {
#ifdef PHUGEPAGE
    unsigned long len = ALIGN(newpbrk - oldpbrk, HPAGE_SIZE);
    unsigned long nr_pages = len / HPAGE_SIZE;
#else
    unsigned long len = PAGE_ALIGN(newpbrk - oldpbrk);
    unsigned long nr_pages = len / PAGE_SIZE;
#endif
    unsigned long start = oldpbrk;
    mm_populate(oldpbrk, newpbrk - oldpbrk);
    // now all physical pages should be filled in
    // find all physical addresses, mimic the behavior in __get_user_pages
    if(nr_pages) {
        // TODO: if the permission is READ only, setup the page permission to READ_ONLY!
        // gup_flags, see populate_vma_page_range in gup.c
        int gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;
        if(target_vma->vm_flags & VM_LOCKONFAULT) {
            gup_flags &= ~FOLL_POPULATE;
        }
        if((target_vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE) {
            gup_flags |= FOLL_WRITE;
        }
        if (target_vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) {
            gup_flags |= FOLL_FORCE;
        }
        do {
            unsigned int foll_flags = gup_flags;
            unsigned int page_increm = 1;
            unsigned int page_mask = 0;
            unsigned long page_frame_addr = pmm_get_ptn_addr(target_vma, start, foll_flags, &page_mask);
            insert_pstore(mm, page_frame_addr, start, 0x644);
            if(page_increm > nr_pages) {
                page_increm = nr_pages;
            }
            // goto the next huge page
#ifdef PHUGEPAGE
            start += page_increm * HPAGE_SIZE;
#else
            start += page_increm * PAGE_SIZE;
#endif
            nr_pages -= page_increm;
        } while(nr_pages);
    }
  }
  // Now: extend all other processes' addrspace attached to this region about the change
  list_for_each(node, &mm->pstore->head) {
    pid_owner = list_entry(node, struct pmm_owner, olist);
    if(pid_owner->pid != current->pid) { // only extend on non-current processes
      struct task_struct *attached = find_task_by_vpid(pid_owner->pid);
      if(attached != NULL) {
	LIST_HEAD(uf);
	struct vm_area_struct *target_vma = NULL;
	int r = 0;
	if(down_write_killable(&attached->mm->mmap_sem)) {
	  printk("Attached process pbrk failed in the middle! -> can't get mmap_sem lock.");
	  return -EINTR;
	}
	if(do_pbrk(attached->mm, oldpbrk, (newpbrk - oldpbrk), &uf, &target_vma) < 0) {
	  printk("Attached process pbrk failed in the middle!");
	  up_write(&attached->mm->mmap_sem);
	  return -ENOMEM;
	}
	// populate to the other process...
	up_write(&attached->mm->mmap_sem);
	r = foreign_mm_populate(attached, attached->mm, oldpbrk, (newpbrk - oldpbrk));
	if(r != 0) {
	  printk("Failed to populate to other attached process: %d", attached->pid);
	}
      } else {
	printk("Attached process exits but not cleared in the pstore! pid=%d", attached->pid);
      } // attached process NULL?
    } // list_for_each
  }
  // update in the end, because when other processes read this pbrk, they should be able to read the memory
  mm->pstore->pbrk = newpbrk;
  return newpbrk;
out:
  retval = mm->pstore->pbrk;
  up_write(&mm->mmap_sem);
  return retval;
}

// save the address in pstore, now we only have one pstore
static void insert_pstore(struct mm_struct* mm,
                          unsigned long paddr, unsigned long vaddr,
                          unsigned long perm) {
  int index;
  if(mm->pstore == NULL) {
    printk("Panic! Why the attached pstore is NULL?");
    return;
  }
  index = mm->pstore->cnt;
  mm->pstore->pages[index].paddr = paddr;
  const struct cred *cred = current_cred();
  mm->pstore->pages[index].euid = cred->euid.val;
  mm->pstore->pages[index].egid = cred->egid.val;
  mm->pstore->pages[index].perm = perm;
  mm->pstore->cnt += 1;
  struct page* page = pfn_to_page(paddr);
  page->pheapPage = 1; // set pheap_page
  return;
}

int do_pbrk(struct mm_struct *mm, unsigned long addr, unsigned long request,
            struct list_head* uf, struct vm_area_struct **target_vma) {
    struct vm_area_struct *vma, *prev;
    unsigned long len;
    unsigned long flags;
    struct rb_node **rb_link, *rb_parent;
    int error;
#ifdef PHUGEPAGE
    pgoff_t pgoff = addr >> HPAGE_SHIFT;
    len = ALIGN(request, HPAGE_SIZE);
#else
    pgoff_t pgoff = addr >> PAGE_SHIFT;
    len = PAGE_ALIGN(request);
#endif
    if (len < request)
        return -ENOMEM;
    if (!len)
        return 0;
    
    // function for this:  transparent_hugepage_enabled()
    // madvise && TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG
#ifdef PHUGEPAGE
    flags = VM_HUGEPAGE;
#else
    flags = 0;
#endif
    flags |= VM_DATA_DEFAULT_FLAGS | VM_ACCOUNT | mm->def_flags;
    error = get_unmapped_area(NULL, addr, len, 0, MAP_FIXED);
    if(offset_in_page(error))
        return error;
    
    error = mlock_future_check(mm, mm->def_flags, len);
    if (error)
        return error;
    
    /*
     * mm-> mmap_sem is required to protect against another thread
     * changing the mappings in case we sleep,
     */
    /* Xu: no need to verify this cuz we are sure it is already locked. */
    // verify_mm_writelocked(mm);
 
    /*
     * Clear old maps. This also does some error checking for us.
     */
    while(find_vma_links(mm, addr, addr+len, &prev, &rb_link, &rb_parent)) {
        if(do_munmap(mm, addr, len, uf)) {
            return -ENOMEM;
        }
    }
    
   	/* Check against address space limits *after* clearing old maps... */
#ifdef PHUGEPAGE
	if (!may_expand_vm(mm, flags, len >> HPAGE_SHIFT))
		return -ENOMEM;

	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	if (security_vm_enough_memory_mm(mm, len >> HPAGE_SHIFT))
		return -ENOMEM;
#else
	if (!may_expand_vm(mm, flags, len >> PAGE_SHIFT))
		return -ENOMEM;

	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	if (security_vm_enough_memory_mm(mm, len >> PAGE_SHIFT))
		return -ENOMEM;
#endif
	/* Can we just expand an old private anonymous mapping? */
	// Persistent memory has different properties so we only merge it with other pmm vma.
	vma = vma_merge(mm, prev, addr, addr + len, flags,
		NULL, NULL, pgoff, NULL, NULL_VM_UFFD_CTX);
    
	if (vma)
		goto out;

	/*
	 * create a vma struct for an anonymous mapping
	 */
	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma) {
#ifdef PHUGEPAGE
		vm_unacct_memory(len >> HPAGE_SHIFT);
#else
		vm_unacct_memory(len >> PAGE_SHIFT);
#endif
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&vma->anon_vma_chain);
	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_pgoff = pgoff;
	vma->vm_flags = flags;
	vma->vm_page_prot = vm_get_page_prot(flags);
	vma_link(mm, vma, prev, rb_link, rb_parent);
out:
	perf_event_mmap(vma);
#ifdef PHUGEPAGE
    mm->total_vm += len >> HPAGE_SHIFT;
	mm->data_vm += len >> HPAGE_SHIFT;
	if (flags & VM_LOCKED)
		mm->locked_vm += (len >> HPAGE_SHIFT);
#else
	mm->total_vm += len >> PAGE_SHIFT;
	mm->data_vm += len >> PAGE_SHIFT;
	if (flags & VM_LOCKED)
		mm->locked_vm += (len >> PAGE_SHIFT);
#endif
	vma->vm_flags |= VM_SOFTDIRTY;
    *target_vma = vma;
	return 0;
}

#ifndef HAVE_ARCH_UNMAPPED_AREA
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	struct vm_unmapped_area_info info;

	if (len > TASK_SIZE - mmap_min_addr)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	if (addr) {
#ifdef PHUGEPAGE
	  addr = ALIGN(addr, HPAGE_SIZE);
#else
	  addr = PAGE_ALIGN(addr);
#endif
	  vma = find_vma_prev(mm, addr, &prev);
	  if (TASK_SIZE - len >= addr && addr >= mmap_min_addr &&
	      (!vma || addr + len <= vm_start_gap(vma)) &&
	      (!prev || addr >= vm_end_gap(prev)))
	    return addr;
	}

	info.flags = 0;
	info.length = len;
	info.low_limit = mm->mmap_base;
	info.high_limit = TASK_SIZE;
	info.align_mask = 0;
	return vm_unmapped_area(&info);
}
#endif

static inline int mlock_future_check(struct mm_struct *mm,
				     unsigned long flags,
				     unsigned long len)
{
	unsigned long locked, lock_limit;

	/*  mlock MCL_FUTURE? */
	if (flags & VM_LOCKED) {
#ifdef PHUGEPAGE     
		locked = len >> HPAGE_SHIFT;
		locked += mm->locked_vm;
		lock_limit = rlimit(RLIMIT_MEMLOCK);
		lock_limit >>= HPAGE_SHIFT;
#else
		locked = len >> PAGE_SHIFT;
		locked += mm->locked_vm;
		lock_limit = rlimit(RLIMIT_MEMLOCK);
		lock_limit >>= PAGE_SHIFT;
#endif
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return -EAGAIN;
	}
	return 0;
}

static int find_vma_links(struct mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}

static long vma_compute_subtree_gap(struct vm_area_struct *vma)
{
	unsigned long max, prev_end, subtree_gap;

	/*
	 * Note: in the rare case of a VM_GROWSDOWN above a VM_GROWSUP, we
	 * allow two stack_guard_gaps between them here, and when choosing
	 * an unmapped area; whereas when expanding we only require one.
	 * That's a little inconsistent, but keeps the code here simpler.
	 */
	max = vm_start_gap(vma);
	if (vma->vm_prev) {
		prev_end = vm_end_gap(vma->vm_prev);
		if (max > prev_end)
			max -= prev_end;
		else
			max = 0;
	}
	if (vma->vm_rb.rb_left) {
		subtree_gap = rb_entry(vma->vm_rb.rb_left,
				struct vm_area_struct, vm_rb)->rb_subtree_gap;
		if (subtree_gap > max)
			max = subtree_gap;
	}
	if (vma->vm_rb.rb_right) {
		subtree_gap = rb_entry(vma->vm_rb.rb_right,
				struct vm_area_struct, vm_rb)->rb_subtree_gap;
		if (subtree_gap > max)
			max = subtree_gap;
	}
	return max;
}

static int browse_rb(struct mm_struct *mm)
{
	struct rb_root *root = &mm->mm_rb;
	int i = 0, j, bug = 0;
	struct rb_node *nd, *pn = NULL;
	unsigned long prev = 0, pend = 0;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		if (vma->vm_start < prev) {
			pr_emerg("vm_start %lx < prev %lx\n",
				  vma->vm_start, prev);
			bug = 1;
		}
		if (vma->vm_start < pend) {
			pr_emerg("vm_start %lx < pend %lx\n",
				  vma->vm_start, pend);
			bug = 1;
		}
		if (vma->vm_start > vma->vm_end) {
			pr_emerg("vm_start %lx > vm_end %lx\n",
				  vma->vm_start, vma->vm_end);
			bug = 1;
		}
		spin_lock(&mm->page_table_lock);
		if (vma->rb_subtree_gap != vma_compute_subtree_gap(vma)) {
			pr_emerg("free gap %lx, correct %lx\n",
			       vma->rb_subtree_gap,
			       vma_compute_subtree_gap(vma));
			bug = 1;
		}
		spin_unlock(&mm->page_table_lock);
		i++;
		pn = nd;
		prev = vma->vm_start;
		pend = vma->vm_end;
	}
	j = 0;
	for (nd = pn; nd; nd = rb_prev(nd))
		j++;
	if (i != j) {
		pr_emerg("backwards %d, forwards %d\n", j, i);
		bug = 1;
	}
	return bug ? -1 : i;
}

static void validate_mm(struct mm_struct *mm)
{
	int bug = 0;
	int i = 0;
	unsigned long highest_address = 0;
	struct vm_area_struct *vma = mm->mmap;

	while (vma) {
		struct anon_vma *anon_vma = vma->anon_vma;
		/*struct anon_vma_chain *avc;*/

		if (anon_vma) {
			/*anon_vma_lock_read(anon_vma);
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				anon_vma_interval_tree_verify(avc);
			anon_vma_unlock_read(anon_vma);*/
		}

		highest_address = vm_end_gap(vma);
		vma = vma->vm_next;
		i++;
	}
	if (i != mm->map_count) {
		pr_emerg("map_count %d vm_next %d\n", mm->map_count, i);
		bug = 1;
	}
	if (highest_address != mm->highest_vm_end) {
		pr_emerg("mm->highest_vm_end %lx, found %lx\n",
			  mm->highest_vm_end, highest_address);
		bug = 1;
	}
	i = browse_rb(mm);
	if (i != mm->map_count) {
		if (i != -1)
			pr_emerg("map_count %d rb %d\n", mm->map_count, i);
		bug = 1;
	}
	VM_BUG_ON_MM(bug, mm);
}

static void __vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	struct vm_area_struct *next;

	vma->vm_prev = prev;
	if (prev) {
		next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			next = rb_entry(rb_parent,
					struct vm_area_struct, vm_rb);
		else
			next = NULL;
	}
	vma->vm_next = next;
	if (next)
		next->vm_prev = vma;
}

static void __vma_link_file(struct vm_area_struct *vma)
{
	/*struct file *file;

	file = vma->vm_file;
	if (file) {
		struct address_space *mapping = file->f_mapping;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&file_inode(file)->i_writecount);
		if (vma->vm_flags & VM_SHARED)
			atomic_inc(&mapping->i_mmap_writable);

		flush_dcache_mmap_lock(mapping);
		vma_interval_tree_insert(vma, &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
	}*/
    return;  /* Xu: We do not consider link file here. */
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent)
{
	struct address_space *mapping = NULL;

	if (vma->vm_file) {
		mapping = vma->vm_file->f_mapping;
		i_mmap_lock_write(mapping);
	}

	__vma_link(mm, vma, prev, rb_link, rb_parent);
	__vma_link_file(vma);

	if (mapping)
		i_mmap_unlock_write(mapping);

	mm->map_count++;
	validate_mm(mm);
}

long foreign_populate_vma_page_range(struct task_struct *tsk,
				     struct mm_struct *mm, struct vm_area_struct *vma,
				     unsigned long start, unsigned long end, int *nonblocking)
{
#ifdef PHUGEPAGE
	unsigned long nr_pages = (end - start) / HPAGE_SIZE;
#else
    unsigned long nr_pages = (end - start) / PAGE_SIZE;
#endif
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_sem), mm);

	gup_flags = FOLL_TOUCH | FOLL_POPULATE | FOLL_MLOCK;
	if (vma->vm_flags & VM_LOCKONFAULT)
		gup_flags &= ~FOLL_POPULATE;
	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	gup_flags |= FOLL_REMOTE; // we are working on non-current tsk/mm because it's remote
	
	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	return get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags,
				NULL, NULL, nonblocking);
}

static int foreign_mm_populate(struct task_struct *tsk,
				struct mm_struct *mm, unsigned long start, unsigned long len) {
  unsigned long end, nstart, nend;
  struct vm_area_struct *vma = NULL;
  int locked = 0;
  long ret = 0;
  int ignore_errors = 1;
  
  VM_BUG_ON(start & ~PAGE_MASK);
#ifdef PHUGEPAGE
  VM_BUG_ON(len != ALIGN(len, HPAGE_SIZE));
#else
  VM_BUG_ON(len != ALIGN(len, PAGE_SIZE));
#endif
  end = start + len;
  
  for (nstart = start; nstart < end; nstart = nend) {
    /*
     * We want to fault in pages for [nstart; end) address range.
     * Find first corresponding VMA.
     */
    if (!locked) {
      locked = 1;
      down_read(&mm->mmap_sem);
      vma = find_vma(mm, nstart);
    } else if (nstart >= vma->vm_end)
      vma = vma->vm_next;
    if (!vma || vma->vm_start >= end)
      break;
    /*
     * Set [nstart; nend) to intersection of desired address
     * range with the first VMA. Also, skip undesirable VMA types.
     */
    nend = min(end, vma->vm_end);
    if (vma->vm_flags & (VM_IO | VM_PFNMAP))
      continue;
    if (nstart < vma->vm_start)
      nstart = vma->vm_start;
    /*
     * Now fault in a range of pages. populate_vma_page_range()
     * double checks the vma flags, so that it won't mlock pages
     * if the vma was already munlocked.
     */
    ret = foreign_populate_vma_page_range(tsk, mm, vma, nstart, nend, &locked);
    if (ret < 0) {
      if (ignore_errors) {
          ret = 0;
          continue;	/* continue at next VMA */
      }
      break;
    }
#ifdef PHUGEPAGE
    nend = nstart + ret * HPAGE_SIZE;
#else
    nend = nstart + ret * PAGE_SIZE;
#endif
    ret = 0;
  }
  if (locked)
    up_read(&mm->mmap_sem);
  return ret;	/* 0 or negative error code */ 
}
