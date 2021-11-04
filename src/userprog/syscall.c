#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

struct syscall_func {
  int num_args;
  void (*func) (uint32_t *, const uint32_t *);
};

static struct syscall_func syscall_map[NUM_SYSCALL];

static void syscall_handler (struct intr_frame *);
static void sys_halt (uint32_t *return_val, const uint32_t *args);
static void sys_exit (uint32_t *return_val, const uint32_t *args);
static void sys_exec (uint32_t *return_val, const uint32_t *args);
static void sys_wait (uint32_t *return_val, const uint32_t *args);
static void sys_create (uint32_t *return_val, const uint32_t *args);
static void sys_remove (uint32_t *return_val, const uint32_t *args);
static void sys_open (uint32_t *return_val, const uint32_t *args);
static void sys_filesize (uint32_t *return_val, const uint32_t *args);
static void sys_read (uint32_t *return_val, const uint32_t *args);
static void sys_write (uint32_t *return_val, const uint32_t *args);
static void sys_seek (uint32_t *return_val, const uint32_t *args);
static void sys_tell (uint32_t *return_val, const uint32_t *args);
static void sys_close (uint32_t *return_val, const uint32_t *args);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_map[SYS_HALT]     = (struct syscall_func) {0, sys_halt};
  syscall_map[SYS_EXIT]     = (struct syscall_func) {1, sys_exit};
  syscall_map[SYS_EXEC]     = (struct syscall_func) {1, sys_exec};
  syscall_map[SYS_WAIT]     = (struct syscall_func) {1, sys_wait};
  syscall_map[SYS_CREATE]   = (struct syscall_func) {2, sys_create};
  syscall_map[SYS_REMOVE]   = (struct syscall_func) {1, sys_remove};
  syscall_map[SYS_OPEN]     = (struct syscall_func) {1, sys_open};
  syscall_map[SYS_FILESIZE] = (struct syscall_func) {1, sys_filesize};
  syscall_map[SYS_READ]     = (struct syscall_func) {3, sys_read};
  syscall_map[SYS_WRITE]    = (struct syscall_func) {3, sys_write};
  syscall_map[SYS_SEEK]     = (struct syscall_func) {2, sys_seek};
  syscall_map[SYS_TELL]     = (struct syscall_func) {1, sys_tell};
  syscall_map[SYS_CLOSE]    = (struct syscall_func) {1, sys_close};
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *arg = (uint32_t*)f->esp;
  // TODO: valid_addr(arg)

  int syscall = *(int *)arg;
  if (syscall < 0 || syscall >= NUM_SYSCALL)
    thread_exit (); // should we do something different??

  struct syscall_func sf = syscall_map[syscall];
  for (int i = 1; i <= sf.num_args; i++) {
    // TODO: check valid_addr(arg + i)
  }

  uint32_t return_val = f->eax;
  sf.func(&return_val, &arg[1]);
  f->eax = return_val;
}

static void
sys_halt (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{
  shutdown_power_off();
}

/* The UNUSED in the below functions will be removed once we implement them */
static void 
sys_exit (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_exec (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_wait (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_create (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_remove (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_open (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_filesize (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_read (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_write (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_seek (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_tell (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}

static void 
sys_close (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{

}
