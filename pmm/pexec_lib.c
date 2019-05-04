#include <linux/mm.h>
#include <linux/fs_struct.h>
#include <linux/tsacct_kern.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/security.h>
#include <linux/compat.h>
#include <linux/elf-randomize.h>
#include <linux/personality.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include <asm/mmu_context.h>

#ifdef CONFIG_MMU
/*
 * The nascent bprm->mm is not visible until exec_mmap() but it can
 * use a lot of memory, account these pages in current->mm temporary
 * for oom_badness()->get_mm_rss(). Once exec succeeds or fails, we
 * change the counter back via acct_arg_size(0).
 */
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
		int write)
{
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;

#ifdef CONFIG_STACK_GROWSUP
	if (write) {
		ret = expand_downwards(bprm->vma, pos);
		if (ret < 0)
			return NULL;
	}
#endif

	if (write)
		gup_flags |= FOLL_WRITE;

	/*
	 * We are doing an exec().  'current' is the process
	 * doing the exec and bprm->mm is the new process's mm.
	 */
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
			&page, NULL, NULL);
	if (ret <= 0)
		return NULL;

	if (write) {
		unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
		unsigned long ptr_size, limit;

		/*
		 * Since the stack will hold pointers to the strings, we
		 * must account for them as well.
		 *
		 * The size calculation is the entire vma while each arg page is
		 * built, so each time we get here it's calculating how far it
		 * is currently (rather than each call being just the newly
		 * added size from the arg page).  As a result, we need to
		 * always add the entire size of the pointers, so that on the
		 * last call to get_arg_page() we'll actually have the entire
		 * correct size.
		 */
		ptr_size = (bprm->argc + bprm->envc) * sizeof(void *);
		if (ptr_size > ULONG_MAX - size)
			goto fail;
		size += ptr_size;

		acct_arg_size(bprm, size / PAGE_SIZE);

		/*
		 * We've historically supported up to 32 pages (ARG_MAX)
		 * of argument strings even with small stacks
		 */
		if (size <= ARG_MAX)
			return page;

		/*
		 * Limit to 1/4 of the max stack size or 3/4 of _STK_LIM
		 * (whichever is smaller) for the argv+env strings.
		 * This ensures that:
		 *  - the remaining binfmt code will not run out of stack space,
		 *  - the program will have a reasonable amount of stack left
		 *    to work from.
		 */
		limit = _STK_LIM / 4 * 3;
		limit = min(limit, rlimit(RLIMIT_STACK) / 4);
		if (size > limit)
			goto fail;
	}

	return page;

fail:
	put_page(page);
	return NULL;
}

static void put_arg_page(struct page *page)
{
	put_page(page);
}

static void free_arg_pages(struct linux_binprm *bprm)
{
}

static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
		struct page *page)
{
	flush_cache_page(bprm->vma, pos, page_to_pfn(page));
}

static int __bprm_mm_init(struct linux_binprm *bprm)
{
	int err;
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = bprm->mm;

	bprm->vma = vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	if (down_write_killable(&mm->mmap_sem)) {
		err = -EINTR;
		goto err_free;
	}
	vma->vm_mm = mm;

	/*
	 * Place the stack at the largest stack address the architecture
	 * supports. Later, we'll move this to an appropriate place. We don't
	 * use STACK_TOP because that can depend on attributes which aren't
	 * configured yet.
	 */
	BUILD_BUG_ON(VM_STACK_FLAGS & VM_STACK_INCOMPLETE_SETUP);
	vma->vm_end = STACK_TOP_MAX;
	vma->vm_start = vma->vm_end - PAGE_SIZE;
	vma->vm_flags = VM_SOFTDIRTY | VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	INIT_LIST_HEAD(&vma->anon_vma_chain);

	err = insert_vm_struct(mm, vma);
	if (err)
		goto err;

	mm->stack_vm = mm->total_vm = 1;
	arch_bprm_mm_init(mm, vma);
	up_write(&mm->mmap_sem);
	bprm->p = vma->vm_end - sizeof(void *);
	return 0;
err:
	up_write(&mm->mmap_sem);
err_free:
	bprm->vma = NULL;
	kmem_cache_free(vm_area_cachep, vma);
	return err;
}

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= MAX_ARG_STRLEN;
}

#else

static inline void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
		int write)
{
	struct page *page;

	page = bprm->page[pos / PAGE_SIZE];
	if (!page && write) {
		page = alloc_page(GFP_HIGHUSER|__GFP_ZERO);
		if (!page)
			return NULL;
		bprm->page[pos / PAGE_SIZE] = page;
	}

	return page;
}

static void put_arg_page(struct page *page)
{
}

static void free_arg_page(struct linux_binprm *bprm, int i)
{
	if (bprm->page[i]) {
		__free_page(bprm->page[i]);
		bprm->page[i] = NULL;
	}
}

static void free_arg_pages(struct linux_binprm *bprm)
{
	int i;

	for (i = 0; i < MAX_ARG_PAGES; i++)
		free_arg_page(bprm, i);
}

static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
		struct page *page)
{
}

static int __bprm_mm_init(struct linux_binprm *bprm)
{
	bprm->p = PAGE_SIZE * MAX_ARG_PAGES - sizeof(void *);
	return 0;
}

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= bprm->p;
}

#endif /* CONFIG_MMU */

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/*
 * 'copy_strings()' copies argument/environment strings from the old
 * processes's memory to the new process's stack.  The call to get_user_pages()
 * ensures the destination page is created and not swapped out.
 */
static int copy_strings(int argc, struct user_arg_ptr argv,
			struct linux_binprm *bprm)
{
	struct page *kmapped_page = NULL;
	char *kaddr = NULL;
	unsigned long kpos = 0;
	int ret;

	while (argc-- > 0) {
		const char __user *str;
		int len;
		unsigned long pos;

		ret = -EFAULT;
		str = get_user_arg_ptr(argv, argc);
		if (IS_ERR(str))
			goto out;

		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len)
			goto out;

		ret = -E2BIG;
		if (!valid_arg_len(bprm, len))
			goto out;

		/* We're going to work our way backwords. */
		pos = bprm->p;
		str += len;
		bprm->p -= len;

		while (len > 0) {
			int offset, bytes_to_copy;

			if (fatal_signal_pending(current)) {
				ret = -ERESTARTNOHAND;
				goto out;
			}
			cond_resched();

			offset = pos % PAGE_SIZE;
			if (offset == 0)
				offset = PAGE_SIZE;

			bytes_to_copy = offset;
			if (bytes_to_copy > len)
				bytes_to_copy = len;

			offset -= bytes_to_copy;
			pos -= bytes_to_copy;
			str -= bytes_to_copy;
			len -= bytes_to_copy;

			if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
				struct page *page;

				page = get_arg_page(bprm, pos, 1);
				if (!page) {
					ret = -E2BIG;
					goto out;
				}

				if (kmapped_page) {
					flush_kernel_dcache_page(kmapped_page);
					kunmap(kmapped_page);
					put_arg_page(kmapped_page);
				}
				kmapped_page = page;
				kaddr = kmap(kmapped_page);
				kpos = pos & PAGE_MASK;
				flush_arg_page(bprm, kpos, kmapped_page);
			}
			if (copy_from_user(kaddr+offset, str, bytes_to_copy)) {
				ret = -EFAULT;
				goto out;
			}
		}
	}
	ret = 0;
out:
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}


/*
 * count() counts the number of strings in array ARGV.
 */
static int count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

static void bprm_fill_uid(struct linux_binprm *bprm)
{
  // ignore the setuid/setgid bits in the file
	/* struct inode *inode; */
	/* unsigned int mode; */
	/* kuid_t uid; */
	/* kgid_t gid; */

	/*
	 * Since this can be called multiple times (via prepare_binprm),
	 * we must clear any previous work done when setting set[ug]id
	 * bits from any earlier bprm->file uses (for example when run
	 * first for a setuid script then again for its interpreter).
	 */
	bprm->cred->euid = current_euid();
	bprm->cred->egid = current_egid();

	/* if (!mnt_may_suid(bprm->file->f_path.mnt)) */
	/* 	return; */

	/* if (task_no_new_privs(current)) */
	/* 	return; */

	/* inode = bprm->file->f_path.dentry->d_inode; */
	/* mode = READ_ONCE(inode->i_mode); */
	/* if (!(mode & (S_ISUID|S_ISGID))) */
	/* 	return; */

	/* Be careful if suid/sgid is set */
	/* inode_lock(inode); */

	/* reload atomically mode/uid/gid now that lock held */
	/* mode = inode->i_mode; */
	/* uid = inode->i_uid; */
	/* gid = inode->i_gid; */
	/* inode_unlock(inode); */

	/* We ignore suid/sgid if there are no mappings for them in the ns */
	/* if (!kuid_has_mapping(bprm->cred->user_ns, uid) || */
	/* 	 !kgid_has_mapping(bprm->cred->user_ns, gid)) */
	/* 	return; */

	/* if (mode & S_ISUID) { */
	/* 	bprm->per_clear |= PER_CLEAR_ON_SETID; */
	/* 	bprm->cred->euid = uid; */
	/* } */

	/* if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) { */
	/* 	bprm->per_clear |= PER_CLEAR_ON_SETID; */
	/* 	bprm->cred->egid = gid; */
	/* } */
}

static void free_bprm(struct linux_binprm *bprm)
{
	free_arg_pages(bprm);
	if (bprm->cred) {
		mutex_unlock(&current->signal->cred_guard_mutex);
		abort_creds(bprm->cred);
	}
	if (bprm->file) {
	  panic("[PMM EXEC] Error! bprm has a file!!");
	}
	/* If a binfmt changed the interp, free it. */
	if (bprm->interp != bprm->filename)
		kfree(bprm->interp);
	kfree(bprm);
}

/*
 * Create a new mm_struct and populate it with a temporary stack
 * vm_area_struct.  We don't have enough context at this point to set the stack
 * flags, permissions, and offset, so we use temporary values.  We'll update
 * them later in setup_arg_pages().
 */
static int bprm_mm_init(struct linux_binprm *bprm)
{
	int err;
	struct mm_struct *mm = NULL;

	bprm->mm = mm = mm_alloc();
	err = -ENOMEM;
	if (!mm)
		goto err;
	bprm->mm->pstore = current->mm->pstore;
	err = __bprm_mm_init(bprm);
	if (err)
		goto err;

	return 0;

err:
	if (mm) {
		bprm->mm = NULL;
		mmdrop(mm);
	}

	return err;
}

