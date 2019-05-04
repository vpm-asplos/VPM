#include "pelfloader_lib.c"

// Needs file related things from bprm:
// bprm->filename
// What we remove/nullize:
// bprm->file == NULL
// current->mm->exec_file == NULL

// Load from elfp+off with total_size to addr.
// Return the adjusted addr map_addr
// Critical function for NoFS
static unsigned long elf_map_mm(unsigned long elfp, unsigned long addr, struct elf_phdr* eppnt,
				int prot, int type, unsigned long total_size) {
  unsigned long map_addr = 0;
  unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
  unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
  char* kbuf = NULL;
  addr = ELF_PAGESTART(addr);
  size = ELF_PAGEALIGN(size);
  if(!size) {
    return addr;
  }
  // total_size if the size of the ELF (interpreter) image
  // The _first_ elf_map needs to know the full size o/w
  // randomization might put this image into an overlapping position
  // with the ELF binary image (since size< total_size)
  // So we first map the 'bit' image - and unmap the remainder at the end
  // mmap flags: MAP_PRIVATE | MAP_DENYWRITE | MAP_FIXED;
  kbuf = kmalloc(size, GFP_KERNEL);
  if(total_size) {
    total_size = ELF_PAGEALIGN(total_size);
    copy_from_user((void*)kbuf, (void __user *)elfp+off, size);
    map_addr = vm_mmap(NULL, addr, total_size, prot, type, 0);
    if(!BAD_ADDR(map_addr)) {
      vm_munmap(map_addr+size, total_size-size);
    }
    // copy the size from elfp+off to map_addr, with size 'size'
    copy_to_user((void __user *)map_addr, (void*)kbuf, size);
  } else {
    copy_from_user((void*)kbuf, (void __user *)elfp+off, size);
    map_addr = vm_mmap(NULL, addr, size, prot, type, 0);
    copy_to_user((void __user *)map_addr, (void*)kbuf, size);
  }
  kfree(kbuf);
  return map_addr;
}

/* This is much more generalized than the library routine read function,
   so we keep this separate.  Technically the library read function
   is only provided so that we can read a.out libraries that have
   an ELF header */
// interp_elf_ex: interpreter header
// interpreter: interp address in the memory
// interp_map_addr:
// no_base: load_bias
// interp_elf_phdata: first interpreter program header
static unsigned long load_elf_interp_mm(struct elfhdr *interp_elf_ex,
					void* interpreter, unsigned long *interp_map_addr,
					unsigned long no_base, struct elf_phdr *interp_elf_phdata) {
  struct elf_phdr *eppnt;
  unsigned long load_addr = 0;
  int load_addr_set = 0;
  unsigned long last_bss = 0, elf_bss = 0;
  int bss_prot = 0;
  unsigned long error = ~0UL;
  unsigned long total_size;
  int i;

  /* First of all, some simple consistency checks */
  if (interp_elf_ex->e_type != ET_EXEC &&
      interp_elf_ex->e_type != ET_DYN) {
    goto out;
  }
  total_size = total_mapping_size(interp_elf_phdata, interp_elf_ex->e_phnum);
  if(!total_size) {
    error = -EINVAL;
    goto out;
  }
  eppnt = interp_elf_phdata;
  for(i = 0; i < interp_elf_ex->e_phnum; i ++, eppnt ++) {
    if (eppnt->p_type == PT_LOAD) {
      // int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
      int elf_type = MAP_PRIVATE;
      int elf_prot = 0;
      unsigned long vaddr = 0;
      unsigned long k, map_addr;
      if (eppnt->p_flags & PF_R) {
	elf_prot = PROT_READ;
	elf_prot |= PROT_WRITE;
      }
      if (eppnt->p_flags & PF_W) {
	elf_prot |= PROT_WRITE;
      }
      if (eppnt->p_flags & PF_X) {
	elf_prot |= PROT_EXEC;
      }
      vaddr = eppnt->p_vaddr;
      if (interp_elf_ex->e_type == ET_EXEC || load_addr_set) {
	elf_type |= MAP_FIXED;
      } else if (no_base && interp_elf_ex->e_type == ET_DYN) {
	load_addr = -vaddr;
      }
      map_addr = elf_map_mm((unsigned long)interpreter, load_addr + vaddr,
			    eppnt, elf_prot, elf_type, total_size);
      total_size = 0;
      if(!*interp_map_addr) {
	*interp_map_addr = map_addr;
      }
      error = map_addr;
      if (BAD_ADDR(map_addr)) {
	goto out;
      }
      if (!load_addr_set &&
	  interp_elf_ex->e_type == ET_DYN) {
	load_addr = map_addr - ELF_PAGESTART(vaddr);
	load_addr_set = 1;
      }
      
      /*
       * Check to see if the section's size will overflow the
       * allowed task size. Note that p_filesz must always be
       * <= p_memsize so it's only necessary to check p_memsz.
       */
      k = load_addr + eppnt->p_vaddr;
      if (BAD_ADDR(k) ||
	  eppnt->p_filesz > eppnt->p_memsz ||
	  eppnt->p_memsz > TASK_SIZE ||
	  TASK_SIZE - eppnt->p_memsz < k) {
	error = -ENOMEM;
	goto out;
      }
      
      /*
       * Find the end of the file mapping for this phdr, and
       * keep track of the largest address we see for this.
       */
      k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
      if (k > elf_bss)
	elf_bss = k;
      
      /*
       * Do the same thing for the memory mapping - between
       * elf_bss and last_bss is the bss section.
       */
      k = load_addr + eppnt->p_vaddr + eppnt->p_memsz;
      if (k > last_bss) {
	last_bss = k;
	bss_prot = elf_prot;
      }
    } // p_type == PT_LOAD
  } // for each eppnt (program header) 
  /*
   * Now fill out the bss section: first pad the last page from the file
   * up to the page boundary, and zero it from elf_bss up to the end of the page.
   * */
  if(padzero(elf_bss)) {
    error = -EFAULT;
    goto out;
  }
  /*
   * Next, align both the file and mem bss up to the page size,
   * since this is where elf_bss was just zeroed up to, and where last_bss
   * will end after the vm_brk_flags() below.
   */
  elf_bss = ELF_PAGEALIGN(elf_bss);
  last_bss = ELF_PAGEALIGN(last_bss);
  /* Finally, if there is still more bss to allocate, do it. */
  if (last_bss > elf_bss) {
    error = vm_brk_flags(elf_bss, last_bss - elf_bss, bss_prot & PROT_EXEC ? VM_EXEC : 0);
    if(error) {
      goto out;
    }
  }
  error = load_addr;
 out:
  return error;
}


#ifndef STACK_RND_MASK
#define STACK_RND_MASK (0x7ff >> (PAGE_SHIFT - 12))	/* 8MB of VA */
#endif

static unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned long random_variable = 0;

	if (current->flags & PF_RANDOMIZE) {
		random_variable = get_random_long();
		random_variable &= STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
}

static struct elf_phdr* load_elf_phdrs_mem(struct elfhdr *elf_ex,
					   void __user * elf_addr) {
  struct elf_phdr *elf_phdata = NULL;
  int retval, size, err = -1;
  loff_t pos = elf_ex->e_phoff;
  /*
   * If the size of this structure has changed, then stop, since
   * we will be doing the wrong thing.
   */
  if(elf_ex->e_phentsize != sizeof(struct elf_phdr)) {
    goto out;
  }

  /* Sanity check the number of program headers... */
  if (elf_ex->e_phnum < 1 ||
      elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr)) {
    goto out;
  }

  /* ...and their total size */
  size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
  if (size > ELF_MIN_ALIGN) {
    goto out;
  }

  elf_phdata = kmalloc(size, GFP_KERNEL);
  if(!elf_phdata) {
    goto out;
  }

  /* Read in the program headers */
  elf_addr += (unsigned long) pos;
  retval = copy_from_user(elf_phdata, elf_addr, size);
  if(retval) {
    err = -EIO;
    goto out;
  }
  // printk("[PMMEXEC] elf hdrs loaded from memory successfully!\n");
  /* Success! */
  err= 0;
 out:
  if(err) {
    kfree(elf_phdata);
    elf_phdata = NULL;
  }
  return elf_phdata;
}

// Input: path name of the elf interpreter, usually ld.so
// Output: a chunk of memory storing the interpreter
struct Prog {
  int id;
  void* map_addr;
  size_t length;
  char name[255];
};

struct pmm_owner {
  pid_t pid;
  unsigned long pbrk_start; // to support address randomization
  struct list_head olist;
};

struct pmm_owner* pmm_get_owner_from_pid(struct pmm_store* pstore, pid_t pid);
int preattach(void);
#define MIN_PBRK 0x2a0002000000

static void pheap_check(void) {
  struct Prog* ldp = NULL;
  unsigned long pmm_start = MIN_PBRK;
  ldp = kmalloc(sizeof(struct Prog), GFP_KERNEL);
  copy_from_user((void*)ldp, (void __user*)pmm_start, sizeof(struct Prog));
  // printk("[PMM] Checking reattached pheap: name of first app: %s", ldp->name);
  copy_from_user((void*)ldp, (void __user*)(pmm_start+sizeof(struct Prog)), sizeof(struct Prog));
  // printk("[PMM] Checking reattached pheap: name of second app: %s", ldp->name);
  kfree(ldp);
}

static void* open_exec_mem(struct linux_binprm* bprm, char* elf_interpreter) {
  unsigned long pmm_start = 0;
  const char* ldname = "ld.so";
  struct pmm_owner* owner = NULL;
  struct Prog* ldp = NULL;
  unsigned int prog_size = sizeof(struct Prog);
  void* retval = NULL;
  unsigned long copyret = 0;
  if(bprm->mm->pstore == NULL) {
    panic("Kernel panic! pmm store is NULL!");
  }
  owner = pmm_get_owner_from_pid(bprm->mm->pstore, current->pid);
  if(owner == NULL) {
    printk("Owner is null so I am returning NULL!\n");
    return NULL;
  }
  pmm_start = owner->pbrk_start;
  // we suppose the ld.so is always the first application...
  ldp = kmalloc(prog_size, GFP_KERNEL);
  copyret = copy_from_user((void*)ldp, (void __user *)pmm_start, prog_size);
  if(copyret) {
    printk("Copying size %u bytes from %p failed!\n", prog_size, (void*)pmm_start);
    return NULL;
  }
  // sanity check.
  if(strcmp(ldp->name, ldname)) {
    printk("Size of Prog: %u, Found name: %s, not %s\n", prog_size, ldp->name, ldname);
    return NULL;
  } else {
    // printk("Found ld.so memory image, address: %p", ldp->map_addr);
    retval = ldp->map_addr;
  }
  kfree(ldp);
  return retval;
}

int load_elf_binary_mem(struct linux_binprm *bprm) {
  void* interpreter = NULL;
  unsigned long load_addr = 0, load_bias = 0;
  int load_addr_set = 0;
  char * elf_interpreter = NULL; // PATH name of the elf interpreter
  unsigned long error;
  struct elf_phdr *elf_ppnt = NULL;
  struct elf_phdr *elf_phdata = NULL; // program headers 
  struct elf_phdr *interp_elf_phdata = NULL;
  unsigned long elf_bss, elf_brk;
  int bss_prot = 0;
  int retval, i;
  unsigned long elf_entry;
  unsigned long interp_load_addr = 0;
  unsigned long start_code, end_code, start_data, end_data;
  unsigned long reloc_func_desc __maybe_unused = 0;
  int executable_stack = EXSTACK_DEFAULT;
  int pattach_ret = 0;
  struct pt_regs *regs = current_pt_regs();
  struct {
    struct elfhdr elf_ex;
    struct elfhdr interp_elf_ex;
  } *loc;
  // struct arch_elf_state arch_state = INIT_ARCH_ELF_STATE;
  // Nofs added
  unsigned long elf_addr = bprm->pmm_addr; // nofs modified
  
  // Journey starts!
  // printk("[PMM] PMM: load elf binary loader start!");
  loc = kmalloc(sizeof(*loc), GFP_KERNEL);
  if(!loc) {
    retval = -ENOMEM;
    printk("[pelfloader] loc alloc failed ...\n");
    goto out_ret;
  }
  /* Get the exec-header */
  loc->elf_ex = *((struct elfhdr *) bprm->buf);
  retval = -ENOEXEC;
  /* First of all, some simple consistency checks */
  if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
    printk("[pelfloader] memcmp failed ...\n");
    goto out;
  }
  if(loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN) {
    printk("[pelfloader] e_type check failed ...\n");
    goto out;
  }
  if(!elf_check_arch(&loc->elf_ex)) {
    goto out;
  }
  elf_phdata = load_elf_phdrs_mem(&loc->elf_ex, (void __user *)bprm->pmm_addr);
  if(!elf_phdata) {
    printk("[pelfloader] load_elf_phdrs_mem failed ...\n");
    goto out;
  }
  
  elf_ppnt = elf_phdata;
  elf_bss = 0;
  elf_brk = 0;

  start_code = ~0UL;
  end_code = 0;
  start_data = 0;
  end_data = 0;
  // printk("Before loading all the headers...");
  for(i = 0; i < loc->elf_ex.e_phnum; i ++) { // for each program header
    if(elf_ppnt->p_type == PT_INTERP)  {
      /* This is the program interpreter used for
       * shared libraries - for now assume that this
       * is an a.out format binary
       */
      retval = -ENOEXEC;
      if(elf_ppnt->p_filesz > PATH_MAX || elf_ppnt->p_filesz < 2) {
	goto out_free_ph;
      }
      retval = -ENOMEM;
      elf_interpreter = kmalloc(elf_ppnt->p_filesz, GFP_KERNEL);
      if(!elf_interpreter) {
	goto out_free_ph;
      }
      // Copy elf_ppnt->p_filesz bytes from the p_offset to get the ELF interpreter name
      retval = copy_from_user(elf_interpreter,
			      (void __user *)(elf_addr+elf_ppnt->p_offset), elf_ppnt->p_filesz);
      if(retval) {
	retval = -EIO;
	goto out_free_interp;
      }
      /* make sure path is NULL terminated */
      retval = -ENOEXEC;
      if(elf_interpreter[elf_ppnt->p_filesz - 1] != '\0') {
	goto out_free_interp;
      }
      // printk("Before opening the interpreter: %s", elf_interpreter);
      // NOFS: Open the elf interpreter from the memory!
      // Load it from the memory and pass as the "interpreter" pointer.
      interpreter = open_exec_mem(bprm, elf_interpreter);
      retval = PTR_ERR(interpreter);
      if (IS_ERR(interpreter)) {
	goto out_free_interp;
      }
      // Nofs: Ignore the memory dump step ... 
      /* Get the interpreter ELF header, put it into loc->interp_elf_ex */
      retval = copy_from_user((void*)&loc->interp_elf_ex, // dest
			      (void*)interpreter, // source
			      sizeof(loc->interp_elf_ex));
      // printk("Copying from user: %p, size: %d, retval = %d\n", (void*) interpreter, sizeof(loc->interp_elf_ex), retval);
      if(retval) {
	printk("error copy from user...\n");
	retval = -EIO;
	goto out_free_dentry;
      }
      // Ignore other headers
      break;
    }
    elf_ppnt++;
  } // end of iterating elf program headers
  // printk("[PMM] Now reach the loading elf program headers!!!"); 
  elf_ppnt = elf_phdata;
  for (i = 0; i < loc->elf_ex.e_phnum; i ++, elf_ppnt++) {
    switch(elf_ppnt->p_type) {
    case PT_GNU_STACK:
      if(elf_ppnt->p_flags & PF_X) {
	executable_stack = EXSTACK_ENABLE_X;
      } else {
	executable_stack = EXSTACK_DISABLE_X;
      }
      break;
    case PT_LOPROC ... PT_HIPROC:
      // Nofs: always proceed. Looks like it is not used on x86
      // see: https://elixir.bootlin.com/linux/v4.13.13/source/fs/binfmt_elf.c#L488
      break;
    }
  }
  /* Some simple consistency checks for the interpreter */
  if (elf_interpreter) { // elf_interpreter stores the path
    retval = -ELIBBAD;
    /* Not an ELF interpreter */
    if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
      goto out_free_dentry;
    }
    /* Verify the interpreter has a valid arch */
    if (!elf_check_arch(&loc->interp_elf_ex)) {
      goto out_free_dentry;
    }
    /* Load the interpreter program haders */
    interp_elf_phdata = load_elf_phdrs_mem(&loc->interp_elf_ex, (void __user *)interpreter);
    if(!interp_elf_phdata) {
      goto out_free_dentry;
    }
    /* Pass PT_LOPROC..PT_HIPROC headers to arch code */
    elf_ppnt = interp_elf_phdata;
    for (i = 0; i < loc->interp_elf_ex.e_phnum; i ++, elf_ppnt++) {
      switch(elf_ppnt->p_type) {
      case PT_LOPROC ... PT_HIPROC:
	// nofs: always proceed
	break;
      }
    }
  } // end of elf_interpreter checks
  
  /* Allow arch code to reject the ELF at this point, whilst it's
   * still possible to return an error to the code that invoked
   * the exec syscall. */
  // nofs: skip checking since it is dummy on x86_64.
  // printk("[PMM] Before reaching the point of no return: before flush_old_exec!!!!!");
  // NoFS: here we reuse the function in exec.c ...
  // This is the point of no return.
  /* Flush all traces of the currently running executable */
  retval = flush_old_exec(bprm);
  if(retval) {
    goto out_free_dentry;
  }
  // printk("[PMM] congrats! you survivied flush_old_exec. \n");

  /* Do this immediately, since STACK_TOP as used in setup_arg_pages 
   * may depend on the personality. */
  SET_PERSONALITY2(loc->elf_ex, &arch_state);
  if(elf_read_implies_exec(loc->elf_ex, executable_stack)) {
    current->personality |= READ_IMPLIES_EXEC;
  }

  if(!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space) {
    current->flags |= PF_RANDOMIZE;
  }

  setup_new_exec(bprm);
  install_exec_creds(bprm);

  /* Do this so that we can load the interpreter, if need be.
   * We will change some of these later. */
  // Nofs: reuse fs function
  retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP), executable_stack);
  if (retval < 0) {
    goto out_free_dentry;
  }
  current->mm->start_stack = bprm->p;

  // printk("[PMM] Before reattaching the pheap!!!");
  /* NOFS: reattach the pheap memory starts */
  pattach_ret = preattach();
  if(pattach_ret != 0) {
    panic("Cannot reattach the pmm region!");
  }
  /* NoFS self check: print the first and second app name. */
  // pheap_check();
  /* NOFS: reattach the pheap memory ends */

  /* Now we do a little grungy work by mmapping the ELF image into
   * the correct location in memory */
  // For each program header in the ELF file
  // Each PT_LOAD header defines a loadable segment,
  // described by the p_filesz and p_memsz
  // The bytes form the file are mapped to the beginning of the memory seg
  // If the segment's memory size is larger than the file size, the "extra"
  // bytes are defined to hold the value 0 and to follow the segment's init area.
  // Loadable segments are sorted by the p_vaddr member

  for(i = 0, elf_ppnt = elf_phdata;
      i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
    int elf_prot = 0, elf_flags;
    unsigned long k, vaddr;
    unsigned long total_size = 0;
    if (elf_ppnt->p_type != PT_LOAD) {
      continue;
    }
    if(unlikely(elf_brk > elf_bss)) {
      unsigned long nbyte;
      retval = set_brk(elf_bss+load_bias, elf_brk+load_bias, bss_prot);
      if(retval) {
	goto out_free_dentry;
      }
      nbyte = ELF_PAGEOFFSET(elf_bss);
      if (nbyte) {
	nbyte = ELF_MIN_ALIGN - nbyte;
	if (nbyte > elf_brk - elf_bss) {
	  nbyte = elf_brk - elf_bss;
	}
	if (clear_user((void __user *)elf_bss + load_bias, nbyte)) {
	  // this bss-zeroing could fail if ELF file adds protections, so we don't check return value
	}
      } // end if nbyte
    } // end unlikely
    if (elf_ppnt->p_flags & PF_R) elf_prot |= PROT_READ;
    if (elf_ppnt->p_flags & PF_W) elf_prot |= PROT_WRITE;
    if (elf_ppnt->p_flags & PF_X) elf_prot |= PROT_EXEC;
    // elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;
    elf_flags = MAP_PRIVATE | MAP_EXECUTABLE;
    elf_prot |= PROT_WRITE;
    vaddr = elf_ppnt->p_vaddr;
    /* If we are loading ET_EXEC or we have already performed
     *  the ET_DYN load_addr calculations, proceed normally */
    if(loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
      elf_flags |= MAP_FIXED;
    } else if (loc->elf_ex.e_type == ET_DYN) {
      if (elf_interpreter) {
	load_bias = ELF_ET_DYN_BASE;
	if (current->flags & PF_RANDOMIZE) {
	  load_bias += arch_mmap_rnd();
	}
	elf_flags |= MAP_FIXED;
      } else {
	load_bias = 0;
      }
      load_bias = ELF_PAGESTART(load_bias - vaddr);
      total_size = total_mapping_size(elf_phdata, loc->elf_ex.e_phnum);
      if (!total_size) {
	retval = -EINVAL;
	goto out_free_dentry;
      }
    } // end of ET_DYN
    // Map from the ELF file:
    // Memory size: total_size
    // Target memory region: load_bias+vaddr
    // printk("Before running elf map from mm!!!");
    error = elf_map_mm(bprm->pmm_addr, load_bias+vaddr, elf_ppnt, elf_prot, elf_flags, total_size);
    // printk("After running elf map mm!!!");
    if(BAD_ADDR(error)) {
      retval = IS_ERR((void*)error) ?
	PTR_ERR((void*)error) : -EINVAL;
      goto out_free_dentry;
    }
    if(!load_addr_set) {
      load_addr_set = 1;
      load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
      if (loc->elf_ex.e_type == ET_DYN) {
	load_bias += error - ELF_PAGESTART(load_bias + vaddr);
	load_addr += load_bias;
	reloc_func_desc = load_bias;
      }
    } // load_addr_set
    k = elf_ppnt->p_vaddr;
    if (k < start_code) {
      start_code = k;
    }
    if (start_data < k) {
      start_data = k;
    }
    if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
	elf_ppnt->p_memsz > TASK_SIZE ||
	TASK_SIZE - elf_ppnt->p_memsz < k) {
      /* set_brk can never work. Avoid overflows. */
      retval = -EINVAL;
      goto out_free_dentry;
    }
      
    k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;
      
    if (k > elf_bss)
      elf_bss = k;
    if ((elf_ppnt->p_flags & PF_X) && end_code < k)
      end_code = k;
    if (end_data < k)
      end_data = k;
    k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
    if (k > elf_brk) {
      bss_prot = elf_prot;
      elf_brk = k;
    }
  }// end of for loop
  loc->elf_ex.e_entry += load_bias;
  elf_bss += load_bias;
  elf_brk += load_bias;
  start_code += load_bias;
  end_code += load_bias;
  start_data += load_bias;
  end_data += load_bias;

  // mmap the pages we need for bss and break sections
  retval = set_brk(elf_bss, elf_brk, bss_prot);
  if(retval) {
    goto out_free_dentry;
  }
  if(likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
    retval = -EFAULT; // Nobody gets to see this, but...
    goto out_free_dentry;
  }
  
  // printk("Before loading the elf interp from mm...");
  if(elf_interpreter) {
    unsigned long interp_map_addr = 0;
    elf_entry = load_elf_interp_mm(&loc->interp_elf_ex,
				    interpreter,
				    &interp_map_addr,
				    load_bias, interp_elf_phdata);
    // printk("After creating elf interp mm!!!");
    if(!IS_ERR((void*)elf_entry)) {
      // load_elf_interp() returns relocation adjustment
      interp_load_addr = elf_entry;
      elf_entry += loc->interp_elf_ex.e_entry;
     //  printk("interp_elf_ex.e_entry: %p, intep_load_addr: %p, final elf_entry: %p",
// 		      (void*)loc->interp_elf_ex.e_entry,
//		      (void*)interp_load_addr,
// 		      (void*)elf_entry);
    }
    if(BAD_ADDR(elf_entry)) {
      retval = IS_ERR((void*)elf_entry) ? (int)elf_entry: -EINVAL;
      goto out_free_dentry;
    }
    reloc_func_desc = interp_load_addr;
    // allow_write_access(interpreter);
    // fput(interpreter);
    kfree(elf_interpreter);
  } else {
    elf_entry = loc->elf_ex.e_entry;
    if (BAD_ADDR(elf_entry)) {
      retval = -EINVAL;
      goto out_free_dentry;
    }
  }

  kfree(interp_elf_phdata);
  kfree(elf_phdata);
  // set_binfmt(&elf_format); // set binfmt in binfmt_elf.c, outside this function
  
#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
  retval = arch_setup_additional_pages(bprm, !!elf_interpreter);
  if(retval < 0) {
    goto out;
  }
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */
  // printk("Before creating elf tables...");
  // No need to change this
  retval = create_elf_tables(bprm, &loc->elf_ex, load_addr, interp_load_addr);
  if(retval < 0) {
    goto out;
  }
  /* N.B. passed_fileno might not be initialized? */
  current->mm->end_code = end_code;
  current->mm->start_code = start_code;
  current->mm->start_data = start_data;
  current->mm->end_data = end_data;
  current->mm->start_stack = bprm->p;
  if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
    current->mm->brk = current->mm->start_brk = arch_randomize_brk(current->mm);
#ifdef compat_brk_randomized
    current->brk_randomized = 1;
#endif
  }
  if (current->personality && MMAP_PAGE_ZERO) {
    /* sigh */
    error = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
		    MAP_FIXED | MAP_PRIVATE, 0);
  }
#ifdef ELF_PLAT_INIT
  ELF_PLAT_INIT(regs, reloc_func_desc);
#endif
  // printk("Finally: before starting the thread!!! elf_entry: %p, bprm->p: %p",
	//	  (void*)elf_entry, (void*)bprm->p);
  start_thread(regs, elf_entry, bprm->p);
  retval = 0;
 out:
  kfree(loc);
 out_ret:
  return retval;
 out_free_dentry:
  kfree(interp_elf_phdata);
 out_free_interp:
  kfree(elf_interpreter);
 out_free_ph:
  kfree(elf_phdata);
  goto out;
} // end of load_elf_binary_mem
