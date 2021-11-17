#include "userprog/files.h"
#include <stdlib.h>
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static hash_hash_func fd_hash;
static hash_less_func fd_less;
static hash_action_func fd_destructor;

static int allocate_fd (struct files *);

/* Mapping from an FD to the file it represents. */
struct file_descriptor
  {
    int fd;                /* The file descriptor. */
    struct hash_elem elem; /* Element for fd_table. */
    struct file *file;     /* The open file. */
  };


/* Returns the files member of the current process. */
struct files *
get_current_files (void)
{
  process_table_lock ();
  struct files *f = &get_process (thread_current ()->tid)->files;
  process_table_unlock ();
  return f;
}

/* Initialises a struct files. */
void 
files_init_files (struct files *f)
{
  f->fd_map = bitmap_create (MAX_FD_COUNT + 3);
  bitmap_set (f->fd_map, FD_STDIN, true);
  bitmap_set (f->fd_map, FD_STDOUT, true);
  hash_init (&f->fd_table, fd_hash, fd_less, f);
}

/* Opens FILE_NAME and returns a newly allocated FD. */
int
files_open (struct files *f, char *file_name)
{
  struct file *opened_file = filesys_open (file_name);
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

/* Checks whether FD is in use. */
bool
files_is_open (struct files *f, int fd)
{
  return (fd >= 0) && (fd < MAX_FD_COUNT + 2) 
    && (bitmap_test (f->fd_map, fd));
}

/* Returns the struct file for FD, or NULL if this FD is not in use. */
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
  e = hash_find (&f->fd_table, &file_desc.elem);
  ASSERT (e != NULL);
  return hash_entry (e, struct file_descriptor, elem)->file;
}

/* Closes FD, removing it from the table and freeing it up to be allocated
   again in the future. */
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

/* Destroys a struct files. */
void
files_destroy_files (struct files *f)
{
  hash_destroy (&f->fd_table, fd_destructor);
  bitmap_destroy (f->fd_map);
}

/* Computes a hash for a file_descriptor. */
static unsigned
fd_hash (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_int (hash_entry (e, struct file_descriptor, elem)->fd);
}

/* Compares two file_descriptors by their FDs. */
static bool
fd_less (const struct hash_elem *a,
         const struct hash_elem *b,
         void *aux UNUSED)
{
  return hash_entry (a, struct file_descriptor, elem)->fd
         < hash_entry (b, struct file_descriptor, elem)->fd;
}

/* Destroys a file_descriptor. It must already have been removed from the
   table. */
static void
fd_destructor (struct hash_elem *e, void *f_)
{
  struct file_descriptor *file_desc = hash_entry (e, struct file_descriptor, elem);
  file_close (file_desc->file);
  bitmap_set (((struct files *) f_)->fd_map, file_desc->fd, false);
  free (file_desc);
}

/* Allocates and returns a new FD. */
static int
allocate_fd (struct files *f)
{
  return (int) bitmap_scan_and_flip (f->fd_map, 2, 1, false);
}