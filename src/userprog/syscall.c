#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

typedef uint32_t (handler_func) (const uint32_t, const uint32_t, const uint32_t);

struct handler {
  int num_args;
  handler_func *func;
};


static void syscall_handler (struct intr_frame *);
static handler_func sys_halt;
static handler_func sys_exit;
static handler_func sys_exec;
static handler_func sys_wait;
static handler_func sys_create;
static handler_func sys_remove;
static handler_func sys_open;
static handler_func sys_filesize;
static handler_func sys_read;
static handler_func sys_write;
static handler_func sys_seek;
static handler_func sys_tell;
static handler_func sys_close;

static struct handler syscall_map[NUM_SYSCALL] =
{
  [SYS_HALT]     = (struct handler) { .num_args = 0, .func = sys_halt},
  [SYS_EXIT]     = (struct handler) { .num_args = 1, .func = sys_exit},
  [SYS_EXEC]     = (struct handler) { .num_args = 1, .func = sys_exec},
  [SYS_WAIT]     = (struct handler) { .num_args = 1, .func = sys_wait},
  [SYS_CREATE]   = (struct handler) { .num_args = 2, .func = sys_create},
  [SYS_REMOVE]   = (struct handler) { .num_args = 1, .func = sys_remove},
  [SYS_OPEN]     = (struct handler) { .num_args = 1, .func = sys_open},
  [SYS_FILESIZE] = (struct handler) { .num_args = 1, .func = sys_filesize},
  [SYS_READ]     = (struct handler) { .num_args = 3, .func = sys_read},
  [SYS_WRITE]    = (struct handler) { .num_args = 3, .func = sys_write},
  [SYS_SEEK]     = (struct handler) { .num_args = 2, .func = sys_seek},
  [SYS_TELL]     = (struct handler) { .num_args = 1, .func = sys_tell},
  [SYS_CLOSE]    = (struct handler) { .num_args = 1, .func = sys_close}
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *param = (uint32_t*)f->esp;
  // TODO: valid_addr(param)

  int syscall = *(int *)param;
  if (syscall < 0 || syscall >= NUM_SYSCALL)
    thread_exit (); // should we do something different??

  struct handler h = syscall_map[syscall];
  uint32_t args[3] = { 0 };
  for (int i = 1; i <= h.num_args; i++) {
    // TODO: check valid_addr(param + i)
    args[i] = *(param + i);
  }

  f->eax = h.func(args[1], args[2], args[3]);
}

static uint32_t
sys_halt (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  shutdown_power_off();
  return 0;
}

/* The UNUSED in the below functions will be removed once we implement them */
static uint32_t 
sys_exit (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_exec (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_wait (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_create (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_remove (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_open (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_filesize (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_read (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_write (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_seek (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_tell (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}

static uint32_t 
sys_close (const uint32_t arg1 UNUSED, const uint32_t arg2 UNUSED, const uint32_t arg3 UNUSED)
{
  return -1;
}
