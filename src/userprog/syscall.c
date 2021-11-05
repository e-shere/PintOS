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

static struct handler syscall_map[NUM_SYSCALL];

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_map[SYS_HALT]     = (struct handler) {0, sys_halt};
  syscall_map[SYS_EXIT]     = (struct handler) {1, sys_exit};
  syscall_map[SYS_EXEC]     = (struct handler) {1, sys_exec};
  syscall_map[SYS_WAIT]     = (struct handler) {1, sys_wait};
  syscall_map[SYS_CREATE]   = (struct handler) {2, sys_create};
  syscall_map[SYS_REMOVE]   = (struct handler) {1, sys_remove};
  syscall_map[SYS_OPEN]     = (struct handler) {1, sys_open};
  syscall_map[SYS_FILESIZE] = (struct handler) {1, sys_filesize};
  syscall_map[SYS_READ]     = (struct handler) {3, sys_read};
  syscall_map[SYS_WRITE]    = (struct handler) {3, sys_write};
  syscall_map[SYS_SEEK]     = (struct handler) {2, sys_seek};
  syscall_map[SYS_TELL]     = (struct handler) {1, sys_tell};
  syscall_map[SYS_CLOSE]    = (struct handler) {1, sys_close};
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
