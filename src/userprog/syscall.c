#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_string (const char *ustr, int max_length);
static bool is_valid_user_address (const uint8_t *uaddr);
static bool is_valid_user_address_range (uint8_t *uaddr, uint32_t size);
static bool get_user_bytes (const uint8_t *uaddr, uint8_t *buf, uint32_t size);
static int get_user_byte (const uint8_t *uaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/* Checks whether the string given by ustr is entirely situated within valid
   user virtual memory. Since we cannot know the length of the string without
   iterating through it, we have to check it byte-by-byte to ensure it will
   not incorrectly run into unallocated memory.

   If max_length is set to < 0, this function will not terminate until it finds
   the end of the string. If it is set to >= 0, then it will return false if
   it has checked max_length + 1 bytes and has not found the null terminator. */
static bool
is_valid_user_string (const char *ustr, int max_length)
{
  int current_byte = (get_user_byte ((uint8_t *) ustr++));
  int current_length = 0;
  while (current_byte != 0)
    {
      if (current_byte == -1
          || !is_user_vaddr (ustr)
          || (max_length > 0 && ++current_length > max_length))
        return false;
      current_byte = (get_user_byte ((uint8_t *) ustr++));
    }
  return true;
}

/* Checks whether the address uaddr is a valid user virtual address. We don't
   want to mess around in the page directory, so we'll just let the MMU
   pagefault us and then recover. */
static bool
is_valid_user_address (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return false;
  return get_user_byte (uaddr) != -1;
}

/* Checks whether the address range starting at start_addr of length size is 
   valid user virtual memory. We assume that end point is still < PHYS_BASE.
   If the 22 most significant bits of the start and end
   points of the range are the same, then they do not cross a page boundary
   and thus the entire range is valid, since memory is only initialized a page
   at a time. Now the difference between the 22 MSBs (page number) of the start
   and end addresses are exactly the number of different pages occupied by the
   range. In this case then, we must check the start address, the end address,
   and one representative from each page between them in the range - since we
   assume that contiguous memory address are not necessarily allocated to
   contiguous pages. We do this by simply adding PGSIZE to the start address
   and then checking the validity of this address until it is greater than the
   end address.
   
   We do not use get_user_byte directly, and insted just verify that buffers
   are in valid address space. The only time we ever want to use buffers in
   syscalls, the addresses will not be dereferenced in this file, and instead
   in other places in the code. This is much more efficient than checking the
   range byte-by-byte (4096x faster for sufficiently large ranges!). */
static bool
is_valid_user_address_range (uint8_t *start_addr, uint32_t size)
{
  uint8_t *end_addr = start_addr + size;

  // Case 1
  if (pg_no (start_addr) == pg_no (end_addr))
    return is_valid_user_address (start_addr);

  // Case 2
  if (!is_valid_user_address (start_addr) || !is_valid_user_address (end_addr))
    return false;
  for (uint8_t *current_addr = start_addr + PGSIZE; 
       current_addr < end_addr;
       current_addr += PGSIZE)
    {
      if (!is_valid_user_address (current_addr))
        return false;
    }

  return true;
}

/* Reads size bytes at user virtual address UADDR into buf
   Returns false if the read failed. */
static bool
get_user_bytes (const uint8_t *uaddr, uint8_t *buf, uint32_t size)
{
  if (!is_user_vaddr (uaddr + size))
    return false;
  
  for (uint32_t i = 0; i < size; i++)
    {
      int current_value = get_user_byte (uaddr + i);
      if (current_value == -1)
        return false;
      buf[i] = current_value;
    }
}

/* Reads a byte at user virtual address UADDR. We assume this is not kernel
   memory. Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user_byte (const uint8_t *uaddr)
{
  int result;
  asm  ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}
