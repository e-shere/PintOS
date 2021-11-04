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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_map[SYS_HALT] = (struct syscall_func) {0, sys_halt};
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

  uint32_t return_val;
  sf.func(&return_val, &arg[1]);
  f->eax = return_val;
}

static void
sys_halt (uint32_t *return_val UNUSED, const uint32_t *args UNUSED)
{
  shutdown_power_off();
}
