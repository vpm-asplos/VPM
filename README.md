Linux kernel 4.14.13 with VPM Support
======================================

## Important notes

VPM is still a research prototype and is subject to change.
We pose the following static limits to the pheap region:

- maximum number of pheap regions `PMM_COUNT_LIMIT = 16`
- maximum number of huge pages per pheap region `MAX_PMM_SIZE = 524288`
- maximum pheap id length `PMMID_LEN_LIMIT = 256 bytes`

## Table of contents

- [pattach](#pattach)
- [pdetach](#pdetach)
- [pchmod](#pchmod)
- [pbrk](#pbrk)

## pattach

Create a new pheap region, or attach to an existing pheap region.

### Synopsis

```C
int pattach (const char* guid, size_t len, unsigned long flag);
```

### Description

NoFS system call `pattach` takes a global unique pheap id(`guid`), its length(`len`), and the argument flag(`flag`). The flag must include one of the following two options: `PHEAP_CREATE`, or `PHEAP_ATTACH`.

* `PHEAP_CREATE` used to create a non-existing pheap with given id.

* `PHEAP_ATTACH` used to attach to an existing pheap with given id.

### Return values

On success it returns 0. On error, `-errno` is returned.

### Errors

If `guid` length exceeds `PMMID_LEN_LIMIT`, return `-EINVAL`.
If `flag` is `PHEAP_CREATE`, and a pheap with `guid` already exists, return `-EINVAL`.
If `flag` is `PHEAP_ATTACH`, and a pheap with `guid` does not exist, return `-EINVAL`.
If the process has already attached to some pheap, and it is trying to attach or create another pheap, return `-EINVAL`;
If `flag` is `PHEAP_ATTACH`, and the caller process does not have sufficient privilege to attach to the specified pheap, return `-EACCES`.

## pdetach

Detach to the process's currently attached pheap region.

### Synopsis

```C
int pdetach(void);
```

### Description

NoFS system call `pdetach` detaches the caller's currently attached pheap.
If the caller does not attach to any pheap at the point of calling `pdetach`, return `-EINVAL`.

### Return values
On success it returns 0. On error, `-EINVAL` is returned.

## pchmod

NoFS system call `pchmod` changes the privilege mode of a pheap region.

### Synopsis

```C
int pchmod(unsigned long mode);
```

### Return values

On success it returns 0. On error it returns `-EACCESS`.

### Errors

- If the caller process does not attach to any pheap, return `-EINVAL`.
- If the caller process does not have sufficient privilege to change the permission, return `-EINACCESS`.

## pbrk

NoFS system call `pbrk` changes the pheap size.

### Synopsis

```C
int pbrk(unsigned long pbrk);
```

### Description

NoFS system call `pbrk` changes the size of the pheap attached by the caller and updates pheap size for all the processes attached to this pheap. We call the pheap attached by the caller process the target pheap.

By default, all memory pages in the pheap region are huge pages.
We will round up the argument `pbrk` to huge page aligned, which is 2M aligned.

If the argument `pbrk` is smaller than the old pheap break, `pbrk()` will shrink the size of the pheap to the argument `pbrk`. If the argument `pbrk` equals to the starting address of the pheap region, shrink the size of pheap to 0.

No matter increase or shrink pheap size, we will update the pheap size for all the processes that are currently attaching to the target pheap.

By default, `pbrk` will populate all the page table entries of the memory pages located in the pheap region.

### Return values

On success, `pbrk` returns the new pheap break.

On error, `pbrk` returns `-errno`.

### Errors

- If current process does not attach to any pheap, return `-EINVAL`.

- If there is not enough physical memory, return `-ENOMEM`.
