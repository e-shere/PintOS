#include "userprog/files.h"
#include <stdlib.h>
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static hash_hash_func fd_hash;
static hash_less_func fd_less;
static hash_action_func fd_destructor;

static int allocate_fd (struct files *);

struct file_descriptor
  {
    int fd;
    struct hash_elem elem;

    struct file *file;
  };


struct files *
get_current_files (void)
{
  process_table_lock ();
  struct files *f = &get_process (thread_current ()->tid)->files;
  process_table_unlock ();
  return f;
}

void 
files_init_files (struct files *f)
{
  f->fd_map = bitmap_create (MAX_FD_COUNT + 3);
  bitmap_set (f->fd_map, FD_STDIN, true);
  bitmap_set (f->fd_map, FD_STDOUT, true);
  hash_init (&f->fd_table, fd_hash, fd_less, f);
}

int
files_open (struct files *f, char *file_name)
{
  lock_acquire(f->file_lock);
  struct file *opened_file = filesys_open (file_name);
  lock_release(f->file_lock);
  if (opened_file == NULL)
    return FD_FAILURE;

  struct file_descriptor *file_desc = malloc (sizeof(struct file_descriptor));
  if (file_desc == NULL)
    return FD_FAILURE;
    
  *file_desc =
  (struct file_descriptor) {
    .fd   = allocate_fd (f),
    .file = opened_file
  };
  hash_insert (&f->fd_table, &file_desc->elem);
  return file_desc->fd;
}

bool
files_is_open (struct files *f, int fd)
{
  return (fd >= 0) && (fd < MAX_FD_COUNT + 2) 
    && (bitmap_test (f->fd_map, fd));
}

struct file *
files_get (struct files *f, int fd)
{

  if (fd < 0) {
    return NULL;
  }

  ASSERT (files_is_open (f, fd));

  struct file_descriptor file_desc;
  struct hash_elem *e;
  
  file_desc.fd = fd;

  process_table_lock ();
  lock_acquire(&get_process(thread_current ()->tid)->process_lock);
  e = hash_find (&f->fd_table, &file_desc.elem);
  lock_release(&get_process(thread_current ()->tid)->process_lock);
  process_table_unlock ();

  ASSERT (e != NULL);
  return hash_entry (e, struct file_descriptor, elem)->file;
}

void
files_close (struct files *f, int fd)
{
  ASSERT (files_is_open (f, fd));
  
  struct file_descriptor fake_file_desc;
  struct hash_elem *e;
  
  fake_file_desc.fd = fd;
  e = hash_delete (&f->fd_table, &fake_file_desc.elem);
  fd_destructor (e, f);
}

void
files_destroy_files (struct files *f)
{
  hash_destroy (&f->fd_table, fd_destructor);
  bitmap_destroy (f->fd_map);
}

static unsigned
fd_hash (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_int (hash_entry (e, struct file_descriptor, elem)->fd);
}


static bool
fd_less (const struct hash_elem *a,
         const struct hash_elem *b,
         void *aux UNUSED)
{
  return hash_entry (a, struct file_descriptor, elem)->fd
         < hash_entry (b, struct file_descriptor, elem)->fd;
}

static void
fd_destructor (struct hash_elem *e, void *f_)
{
  struct file_descriptor *file_desc = hash_entry (e, struct file_descriptor, elem);
  file_close (file_desc->file);
  bitmap_set (((struct files *) f_)->fd_map, file_desc->fd, false);
  free (file_desc);
}

static int
allocate_fd (struct files *f)
{
  return (int) bitmap_scan_and_flip (f->fd_map, 2, 1, false);
}