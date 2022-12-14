#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/files.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"

#define STATUS_ERROR -1
#define FILESIZE_ERROR -1
#define MIN_FILE_FD 2

typedef uint32_t (handler_func) (const void *, const void *, const void *);

/* Information about a syscall handler. */
struct handler
{
    int num_args;                 /* Number of arguments the syscall takes */
    handler_func *func;           /* Function implementing the syscall */
};

/* Lock controlling access to the file system. */
static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static bool is_valid_user_string (const char *ustr, int max_length);
static bool is_valid_user_address (const uint8_t *uaddr);
static bool is_valid_user_address_range (uint8_t *uaddr, uint32_t size);
static int get_user_byte (const uint8_t *uaddr);

static pid_t tid_to_pid (tid_t);

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
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t *param = (uint32_t *) f->esp;
  if (!is_valid_user_address_range ((uint8_t *) param, sizeof (uint32_t *)))
    {
      process_exit_with_status (STATUS_ERROR);
      return;
    }
  int syscall = *(int *) param;
  if (syscall < 0 || syscall >= NUM_SYSCALL)
    process_exit_with_status (STATUS_ERROR);

  struct handler h = syscall_map[syscall];
  void *args[3] = { 0 };
  if (!is_valid_user_address_range ((uint8_t *) (param + 1),
                                    h.num_args * (sizeof (uint32_t *))))
    {
      process_exit_with_status (STATUS_ERROR);
      return;
    }
  for (int i = 1; i <= h.num_args; i++)
    args[i - 1] = (void *) (param + i);

  /* Sets return value of the syscall */
  f->eax = h.func (args[0], args[1], args[2]);
}

/* Returns the PID of the program running in thread TID. */
static pid_t
tid_to_pid (tid_t tid)
{
  return (pid_t) tid;
}

/* Reads size bytes from the keyboard into buffer, which is in user space.
   Kills the process if the buffer cannot be written to. */
static void
read_keyboard (const void *buffer, unsigned size)
{
  for (unsigned i = 0; i < size; i++)
    *(uint8_t *)(buffer + i) = input_getc();
}

/* Reads size bytes into buffer from file with given file descriptor fd.
   If the buffer cannot be written to, this kills the process. */
static int
read_from_file (int fd, const void *buffer, unsigned size)
{

  uint8_t *buff = (uint8_t *) buffer;

  if (!is_valid_user_address_range (buff, size))
    process_exit_with_status (STATUS_ERROR);


  struct files *current_files = get_current_files ();

  if (!files_is_open (current_files, fd))
    return 0;

  lock_acquire (&filesys_lock);
  struct file *open_file = files_get (current_files, fd);

  int total_chars_read = file_read (open_file, buff, size);
  lock_release (&filesys_lock);

  return total_chars_read;
}

static uint32_t
sys_halt (const void *arg1 UNUSED,
          const void *arg2 UNUSED,
          const void *arg3 UNUSED)
{
  shutdown_power_off ();
  NOT_REACHED ();
  return 0;
}

static uint32_t
sys_exit (const void *status_,
          const void *arg2 UNUSED,
          const void *arg3 UNUSED)
{
  int status = *(int *) status_;
  process_exit_with_status (status);
  NOT_REACHED ();
  return 0;
}

static uint32_t
sys_exec (const void *file, const void *arg2 UNUSED, const void *arg3 UNUSED)
{
  char *cmd_line = *(char **) file;
  if (!is_valid_user_string (cmd_line, PGSIZE))
    return tid_to_pid (TID_ERROR);
  lock_acquire (&filesys_lock);
  tid_t tid = process_execute (cmd_line);
  lock_release (&filesys_lock);
  return tid_to_pid (tid);
}

static uint32_t
sys_wait (const void *tid_, const void *arg2 UNUSED, const void *arg3 UNUSED)
{
  tid_t tid = *(tid_t *) tid_;
  return process_wait (tid);
}

static uint32_t
sys_create (const void *filename_,
            const void *initial_size_,
            const void *arg3 UNUSED)
{
  char *filename = *(char **) filename_;
  if (!is_valid_user_string (filename, PGSIZE))
    process_exit_with_status (STATUS_ERROR);

  uint32_t initial_size = *(uint32_t *) initial_size_;

  lock_acquire (&filesys_lock);
  bool return_value = filesys_create (filename, initial_size);
  lock_release (&filesys_lock);

  return return_value;
}

static uint32_t
sys_remove (const void *filename_,
            const void *arg2 UNUSED,
            const void *arg3 UNUSED)
{
  char *filename = *(char **) filename_;
  if (!is_valid_user_string (filename, PGSIZE))
    process_exit_with_status (STATUS_ERROR);

  lock_acquire (&filesys_lock);
  bool return_value = filesys_remove (filename);
  lock_release (&filesys_lock);

  return return_value;
}

/* open syscall - most processing is offloaded to files_open */
static uint32_t
sys_open (const void *filename_,
          const void *arg2 UNUSED,
          const void *arg3 UNUSED)
{
  char *filename = *(char **) filename_;
  if (!is_valid_user_string (filename, PGSIZE))
    process_exit_with_status (STATUS_ERROR);

  struct files *current_files = get_current_files ();
  lock_acquire (&filesys_lock);
  int fd = files_open (current_files, filename);
  lock_release (&filesys_lock);
  return fd;
}

static uint32_t
sys_filesize (const void *fd_,
              const void *arg2 UNUSED,
              const void *arg3 UNUSED)
{
  uint32_t fd = *(uint32_t *) fd_;
  struct files *current_files = get_current_files ();

  /* We cannot request the filesize of stdin or stdout */
  if (fd < MIN_FILE_FD || !files_is_open (current_files, fd))
    return FILESIZE_ERROR;

  struct file *open_file = files_get (current_files, fd);

  lock_acquire (&filesys_lock);
  off_t open_file_length = file_length (open_file);
  lock_release (&filesys_lock);

  return open_file_length;
}

static uint32_t
sys_read (const void *fd_, const void *buffer_, const void *size_)
{
  int fd = *(int *) fd_;
  unsigned size = *(unsigned *) size_;
  unsigned bytes_written;
  const void *buffer = *(const void **) buffer_;

  if (fd == FD_STDOUT)
    bytes_written = 0;
  else if (fd == FD_STDIN)
    {
      read_keyboard (buffer, size);
      bytes_written = size;
    }
  else
    bytes_written = read_from_file (fd, buffer, size);

  return bytes_written;
}

static uint32_t
sys_write (const void *fd_, const void *buffer_, const void *size_)
{
  int fd = *(int *) fd_;
  unsigned size = *(unsigned *) size_;
  const void *buffer = *(const void **) buffer_;
  if (buffer == NULL
      || !is_valid_user_address_range ((uint8_t *) buffer, size))
    {
      process_exit_with_status (STATUS_ERROR);
      NOT_REACHED ();
      return 0;
    }
  unsigned bytes_written = 0;

  if (fd == FD_STDOUT)
    {
      putbuf (buffer, size);
      bytes_written = size;
    }
  else
    {
      struct files *current_files = get_current_files ();

      if (fd == FD_STDIN || !files_is_open (current_files, fd))
        return 0;

      struct file *open_file = files_get (current_files, fd);
      ASSERT (open_file != NULL)

      lock_acquire (&filesys_lock);
      bytes_written = (unsigned) file_write (open_file, buffer, size);
      lock_release (&filesys_lock);
    }

  return bytes_written;
}

static uint32_t
sys_seek (const void *fd_, const void *position_, const void *arg3 UNUSED)
{
  uint32_t fd = *(uint32_t *) fd_;
  uint32_t position = *(uint32_t *) position_;
  struct files *current_files = get_current_files ();

  /* Again, we cannot execute this function on STDIN or STDOUT */
  if (fd >= MIN_FILE_FD && files_is_open (current_files, fd))
    file_seek (files_get (current_files, fd), position);
  return 0;
}

static uint32_t
sys_tell (const void *fd_, const void *arg2 UNUSED, const void *arg3 UNUSED)
{
  uint32_t fd = *(uint32_t *) fd_;
  struct files *current_files = get_current_files ();

  /* Again, we cannot execute this function on STDIN or STDOUT */
  if (fd >= MIN_FILE_FD && files_is_open (current_files, fd))
    return file_tell (files_get (current_files, fd));

  return STATUS_ERROR;
}

static uint32_t
sys_close (const void *fd_, const void *arg2 UNUSED, const void *arg3 UNUSED)
{
  int fd = *(int *) fd_;

  struct files *current_files = get_current_files ();

  /* Again, we cannot execute this function on STDIN or STDOUT */
  if (files_is_open (current_files, fd) && (fd >= MIN_FILE_FD))
    files_close (current_files, fd);

  return 0;
}

/* Checks whether the string given by ustr is entirely situated within valid
   user virtual memory. Since we cannot know the length of the string without
   iterating through it, we have to check it byte-by-byte to ensure it will
   not incorrectly run into unallocated memory.

   If max_length is set to < 0, this function will not terminate until it finds
   the end of the string. If it is set to >= 0, then it will return false if
   it has checked max_length + 1 bytes and has not found the null terminator.*/
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
  if (pg_no (start_addr) == pg_no (end_addr))
    return is_valid_user_address (start_addr);

  if (!is_valid_user_address (start_addr)
      || !is_valid_user_address (end_addr - 1))
    return false;
  for (uint8_t *current_addr = start_addr + PGSIZE;
       current_addr < end_addr - 1;
       current_addr += PGSIZE)
    {
      if (pg_no (current_addr) == pg_no (end_addr))
        break;
      if (!is_valid_user_address (current_addr))
        return false;
    }

  return true;
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
