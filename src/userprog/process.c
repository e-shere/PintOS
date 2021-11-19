#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/files.h"
#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define put_arg_on_stack(esp, type, value) \
  do                                       \
  {                                        \
    esp -= sizeof (type);		               \
    *(type) esp = value;                   \
  } while (0)

/* A parent's information about one of its children. */
struct child
  {
    tid_t tid;                     /* TID of the child thread. */
    struct hash_elem elem;         /* Element for user_prog.children. */
    struct guard *guard;           /* Guard for relationship with the child */
  };

/* Controls access to a relationship. Needed so parent can free relationship
   upon exiting without leaving the child with an invalid pointer. */
struct guard
  {
    struct lock lock;                      /* Controls access to relationship */
    struct relationship *relationship;     /* Stores exit status of child and
                                              controls waiting */
  };

/* Shared data between parent's process_wait () and the child's
   process_exit (). */
struct relationship
  {
    int exit_status;              /* Exit status of the child */
    struct semaphore wait_sema;   /* Controls waiting on child termination */
  };

static hash_hash_func child_hash;
static hash_less_func child_less;
static hash_action_func destroy_child;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Data shared between process_execute and start_process. */
struct arguments
  {
    int argc;                          /* Number of arguments */
    char **argv;                       /* Pointers to arguments */
    struct semaphore start_sema;       /* Prevents process_execute from exiting
                                          before start_process finishes */
    bool start_success;                /* Whether start_process succeeded */
    struct guard *guard;               /* Guard for parent/child
                                          relationship */
  };

/* Starts a new thread running a user program loaded from
   ARGS_STR.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *args_str)
{
  /* The address where the first argument begins */
  struct arguments *args;
  size_t space_left;

  /* The total length of args_str. */
  size_t length;
  char *save_ptr;
  tid_t tid;

  /* Page of data shared between execute and start.
    args is a struct arguments * but because it
    is at the start of the page, we can use it to refer
    to the whole of the page.
    This page will also contain the whole argument string and argv.
    We put argv at the end because otherwise we would need to
    leave space for it, but we do not know its length until after
    arg_str has been processed which happens after it has
    been copied to the page. */
  args = palloc_get_page (PAL_ZERO);
  if (args == NULL)
    return TID_ERROR;

  sema_init (&args->start_sema, 0);

  size_t reserved_space_on_thread_page = sizeof (void *); /* Return address. */
  reserved_space_on_thread_page += sizeof (int); /* argc */
  reserved_space_on_thread_page += sizeof (char **); /* argv */
  reserved_space_on_thread_page += sizeof (char *); /* argv[0] */
  reserved_space_on_thread_page += sizeof (uint8_t) * 4; /* Word alignment. */
  size_t reserved_space_on_args_page = sizeof (*args);
  reserved_space_on_args_page += sizeof (char *); /* argv[0] */

  /* The data about to be saved on the args page will also need to fit on
     the stack so if there is more space reserved on the stack page we need
     to reserve that amount of space on the temporary args page as well. */
  if (reserved_space_on_thread_page > reserved_space_on_args_page)
    reserved_space_on_args_page = reserved_space_on_thread_page;

  /* Subtract the new maximum value from PGSIZE. */
  space_left = PGSIZE - reserved_space_on_args_page;

  /* args_str will be placed directly after args in the page. */
  char *args_str_ptr = (char *) (((uint8_t *) args) + sizeof (*args));
  length = strlcpy (args_str_ptr, args_str, space_left);

  space_left -= length;
  if (args_str[length] != '\0')
    {
      /* args_str was longer than space_left, we could not fit it all. */
      free (args);
      return TID_ERROR;
    }

  /* We know where the string starts and how long it is, so we can
     find the first space after it which is where we place argv. */
  args->argv = (char **) (args_str_ptr + length + 1);
  args->argv[0] = args_str_ptr;

  strtok_r (args->argv[0], " ", &save_ptr);
  while (args->argv[args->argc] != NULL)
    {
      if (space_left < sizeof (char *))
        {
          /* Not enough space for another argument pointer. */
          free (args);
          return TID_ERROR;
        }
      args->argc++;
      char *arg = strtok_r (NULL, " ", &save_ptr);
      args->argv[args->argc] = arg;
      space_left -= sizeof (arg);
    }

  struct thread *t = thread_current ();
  struct child *child = malloc (sizeof (struct child));
  if (child == NULL)
    {
      /* Since args is at the start of the page, this frees the whole page. */
      palloc_free_page (args);
      return TID_ERROR;
    }
  if (!t->children_initialised)
    {
      hash_init (&t->children, child_hash, child_less, NULL);
      t->children_initialised = true;
    }

  child->guard = malloc (sizeof (struct guard));
  if (child->guard == NULL)
    {
      free (child);
      palloc_free_page (args);
      return TID_ERROR;
    }
  args->guard = child->guard;
  lock_init (&child->guard->lock);

  child->guard->relationship = malloc (sizeof (struct relationship));
  if (child->guard->relationship == NULL)
    {
      free (child->guard);
      free (child);
      palloc_free_page (args);
      return TID_ERROR;
    }
  sema_init (&child->guard->relationship->wait_sema, 0);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args->argv[0], PRI_DEFAULT, start_process, args);
  if (tid == TID_ERROR)
    {
      free (child->guard->relationship);
      free (child->guard);
      free (child);
      palloc_free_page (args);
      return TID_ERROR;
    }
  sema_down (&args->start_sema);
  if (!args->start_success)
    {
      free (child->guard->relationship);
      free (child->guard);
      free (child);
      palloc_free_page (args);
      return TID_ERROR;
    }
  palloc_free_page (args);
  child->tid = tid;
  hash_insert (&t->children, &child->elem);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct arguments *args = args_;
  char *file_name = args->argv[0];
  struct intr_frame if_;
  struct file *executable;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  executable = filesys_open (file_name);

  if (executable == NULL)
    {
      sema_up (&args->start_sema);
      thread_exit ();
    }

  file_deny_write (executable);

  args->start_success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  if (!args->start_success)
    {
      sema_up (&args->start_sema);
      thread_exit ();
    }

  /* Decrement before writing anything to avoid overwriting PHYS_BASE. */
  if_.esp--;
  for (int i = args->argc - 1; i >= 0; i--)
    {
      char *arg = args->argv[i];
      int length = strlen (arg);
      if_.esp -= length + 1;
      strlcpy (if_.esp, arg, length + 1);

      /* Remember where this string was saved. */
      args->argv[i] = if_.esp;
    }
  /* Round down to the nearest multiple of 4 to ensure word-alignment. */
  if_.esp = ((void *) (((unsigned int) if_.esp) / 4 * 4));

  /* Null pointer sentinel. */
  put_arg_on_stack (if_.esp, uint8_t **, NULL);

  for (int i = args->argc - 1; i >= 0; i--)
    {
      put_arg_on_stack (if_.esp, char **, args->argv[i]);
    }

  /* Remember where argv starts. */
  args->argv = if_.esp;
  put_arg_on_stack (if_.esp, char ***, args->argv);
  put_arg_on_stack (if_.esp, int *, args->argc);
  put_arg_on_stack (if_.esp, uint8_t **, NULL);

  struct user_prog *user_prog = malloc (sizeof (struct user_prog));

  if (user_prog == NULL)
    {
      args->start_success = false;
      sema_up (&args->start_sema);
      thread_exit ();
    }

  thread_current ()->user_prog = user_prog;
  user_prog->parent = args->guard;
  user_prog->executable = executable;
  files_init_files (&user_prog->files);

  sema_up (&args->start_sema);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Computes a hash for a child. */
static unsigned
child_hash (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_int (hash_entry (e, struct child, elem)->tid);
}

/* Compares two children by their TIDs. */
static bool
child_less (const struct hash_elem *a,
            const struct hash_elem *b,
            void *aux UNUSED)
{
  return hash_entry (a, struct child, elem)->tid
         < hash_entry (b, struct child, elem)->tid;
}

/* Waits for thread TID to die and returns its exit status.
 * If it was terminated by the kernel (i.e. killed due to an exception),
 * returns -1.
 * If TID is invalid or if it was not a child of the calling process, or if
 * process_wait() has already been successfully called for the given TID,
 * returns -1 immediately, without waiting.
 *
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid)
{
  if (!thread_current ()->children_initialised)
    {
      /* This process has never called process_execute, so it cannot have any
         children. */
      return TID_ERROR;
    }

  struct hash_elem *e;
  struct child fake_child;
  struct child *child;
  struct hash *children = &thread_current ()->children;
  fake_child.tid = child_tid;

  e = hash_find (children, &fake_child.elem);
  if (e == NULL)
    {
      /* CHILD_TID is not a child of this thread or has already been waited
         on. */
      return TID_ERROR;
    }
  child = hash_entry (e, struct child, elem);
  struct relationship *relationship = child->guard->relationship;

  sema_down (&relationship->wait_sema);

  lock_acquire (&child->guard->lock);

  int status = relationship->exit_status;

  free (relationship);
  free (child->guard);
  hash_delete (children, &child->elem);
  free (child);
  return status;
}

/* Terminate the currently running user program with EXIT_STATUS. */
void
process_exit_with_status (int exit_status)
{
  printf ("%s: exit(%d)\n", thread_current ()->name, exit_status);

  struct user_prog *user_prog = thread_current ()->user_prog;
  if (thread_current ()->children_initialised)
    {
      struct hash *children = &thread_current ()->children;
      hash_destroy (children, destroy_child);
    }

  struct guard *parent = user_prog->parent;
  lock_acquire (&parent->lock);
  struct relationship *relationship = parent->relationship;

  if (relationship == NULL)
    free (parent);
  else
    {
      relationship->exit_status = exit_status;
      sema_up (&relationship->wait_sema);
      lock_release (&parent->lock);
    }

  file_close (user_prog->executable);
  files_destroy_files (&user_prog->files);
  free (user_prog);

  thread_exit ();
  NOT_REACHED ();
}

static void
destroy_child (struct hash_elem *e, void *aux UNUSED)
{
  struct child *child = hash_entry (e, struct child, elem);
  struct guard *guard = child->guard;

  lock_acquire (&guard->lock);
  struct relationship *relationship = guard->relationship;

  bool child_has_exited = sema_try_down (&relationship->wait_sema);
  free (relationship);
  free (child);

  if (child_has_exited)
    free (guard);
  else
    {
      guard->relationship = NULL;
      lock_release (&guard->lock);
    }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);

      if (kpage == NULL){

        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
          return false;
        }

        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
