#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

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

int write (int fd, const void *buffer, unsigned size) 
 {
  if (buffer = NULL || !is_user_vaddr(buffer)) 
  {
    return -1
  }

  unsigned bytes_written = 0;

  if (fd == 1) {
    putbuf(buffer, size);
    bytes_written = size;
  }

  return bytes_written;
}