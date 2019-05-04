#include "pexec_lib.c"
#include <linux/cn_proc.h>
#include <linux/ptrace.h>

/*
 * cycle the list of binary formats handler, until one recognizes the image
 */
// first 128 bytes is already loaded into bprm->buf
int search_binary_handler_pmm(struct linux_binprm *bprm)
{
  // call the existing function
  return search_binary_handler(bprm);
}

// bprm->buf[BINPRM_BUF_SIZE]: first 128 bytes of the ELF file
// bprm->vma = STACK_TOP_MAX - (STACK_TOP_MAX - sizeof(void*));
// bprm->p: current top of mem: vma->vm_end - sizeof(void*); in __bprm_mm_init
// bprm->argc, envc: number of args and envs
// bprm->filename: const char * to file name
// bprm->interp: const char * to interpreter
// bprm->cred: struct cred * to new credentials
static int exec_binprm_mem(struct linux_binprm *bprm) {
  pid_t old_pid, old_vpid;
  int ret;
  
  old_pid = current->pid;
  old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
  rcu_read_unlock();

  ret = search_binary_handler_pmm(bprm);
  if (ret >= 0) {
    // audit_bprm(bprm);
    // trace_sched_process_exec(current, old_pid, bprm);
    // ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
    proc_exec_connector(current);
    // printk("[PMM] exec binprm returns: search_binary_handler_pmm return >= zero: %d", ret);
  }
  if(ret != 0) {
	  printk("[PMM] search_binary_handler_pmm return non-zero: %d....", ret);
  }
  return ret;
}

/* 
 * Fill the binprm structure from the memory.
 * Check permissions, then read the first 128 bytes,
 * 
 * This may be called multiple times for binary chains (scripts for example)
 */
static int prepare_binprm_pmm(struct linux_binprm *bprm) {
  /* We don't check cred for now */
  bprm_fill_uid(bprm);
  /* retval = security_bprm_set_creds(bprm); */
  /* if(retval) { */
  /*   return retval; */
  /* } */
  bprm->called_set_creds = 1;
  memset(bprm->buf, 0, BINPRM_BUF_SIZE);
  // read BINPRM_BUF_SIZE from bprm->pmm_addr to bprm_buf
  // BINPRM_BUF_SIZE == 128 (defined in binfmts.h)
  copy_from_user(bprm->buf, (void __user *) bprm->pmm_addr, BINPRM_BUF_SIZE);
  // memcpy always successes
  return 0;
}

// filename should be NULL
int do_execveat_common_pmm(struct linux_binprm *bprm,
			   struct user_arg_ptr argv, struct user_arg_ptr envp, int flags) {
  int retval;
  // execve() is a valuable balancing opportunity, because at this point
  // the task has the smallest effective memory and cache footprint.
  sched_exec();
  // skip all the file part
  retval = bprm_mm_init(bprm); // no need to change
  if(retval) {
    printk("pmm failed: bprm_mm_init failed!");
    goto out_unmark;
  }
  bprm->argc = count(argv, MAX_ARG_STRINGS);
  if((retval = bprm->argc) < 0) {
    goto out;
  }
  bprm->envc = count(envp, MAX_ARG_STRINGS);
  if((retval = bprm->envc) < 0) {
    goto out;
  }
  retval = prepare_binprm_pmm(bprm); // Done
  if(retval < 0) {
	  printk("pmm failed: prepare_bprm_pmm failed!");
    goto out;
  }
  
  bprm->exec = bprm->p; // set bprm->exec
  retval = copy_strings(bprm->envc, envp, bprm);
  if(retval < 0) {
    goto out;
  }
  retval = copy_strings(bprm->argc, argv, bprm);
  if(retval < 0) {
    goto out;
  }
  retval = exec_binprm_mem(bprm); // working horse
  // printk("[PMM] We have returned from exec, retval: %d", retval);
  if(retval < 0) {
    printk("Exec binprm mem failed!");
    goto out;
  }
  
  /* execve succeeded, now clean up */
  current->fs->in_exec = 0;
  current->in_execve = 0;
  membarrier_execve(current);
  // acct_update_integrals(current); // outside
  // task_numa_free(current); // outside
  free_bprm(bprm);
  // kfree(pathbuf); // no need
  // putname(filename); // outside
  // displaced // outside
  // printk("[PMM] EXECVE succeeded, now returning retval=%d", retval);
  return retval;
 out:
  if(bprm->mm) {
    acct_arg_size(bprm, 0);
    mmput(bprm->mm);
  }
 out_unmark:
  current->fs->in_exec = 0;
  current->in_execve = 0;
  free_bprm(bprm);
  // noneed for kfree(pathbuf);
  // outside displaced
  // putname(filename);
  return retval;
}
