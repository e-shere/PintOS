#include "userprog/files.h"
#include <stdlib.h>
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static hash_hash_func fd_hash;
static hash_less_func fd_less;

static int allocate_fd (struct files *);

struct file_descriptor
  {
    int fd;
    struct hash_elem elem;

    struct file *file;
  };


struct files
get_current_files ()
{
  return get_process (thread_current ()->tid)->files;
}

void 
files_init_files (struct files *f)
{
  f->fd_map = bitmap_create (MAX_FILE_COUNT + 3);
  bitmap_set (f->fd_map, 0, true);
  bitmap_set (f->fd_map, 1, true);
  hash_init (&f->fd_table, fd_hash, fd_less, NULL);
}

int
files_open (struct files *f, char *file_name)
{
  struct file_descriptor *file_desc = malloc (sizeof(struct file_descriptor));
  *file_desc =
  (struct file_descriptor) {
    .fd   = allocate_fd (f),
    .file = filesys_open (file_name)
  };
  hash_insert (&f->fd_table, &file_desc->elem);
  return file_desc->fd;
}

bool
files_is_open (struct files *f, int fd)
{
  return bitmap_test (f->fd_map, fd);
}

struct file *
files_get (struct files *f, int fd)
{
  ASSERT (files_is_open (f, fd));

  struct file_descriptor file_desc;
  struct hash_elem *e;
  
  file_desc.fd = fd;
  e = hash_find (&f->fd_table, &file_desc.elem);
  ASSERT (e != NULL);
  return hash_entry (e, struct file_descriptor, elem)->file;
}

void
files_close (struct files *f, int fd)
{
  ASSERT (files_is_open (f, fd));
  
  struct file_descriptor *file_desc;
  struct file_descriptor fake_file_desc;
  struct hash_elem *e;
  
  fake_file_desc.fd = fd;
  e = hash_delete (&f->fd_table, &fake_file_desc.elem);
  ASSERT (e != NULL);
  file_desc = hash_entry (e, struct file_descriptor, elem);
  file_close (file_desc->file);
  free (file_desc);
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

static int
allocate_fd (struct files *f)
{
  return (int) bitmap_scan_and_flip (f->fd_map, 2, 1, false);
}