#include "userprog/files.h"

static hash_hash_func fd_hash;
static hash_less_func fd_less;

static int allocate_fd (struct files *);

struct file_descriptor
  {
    int fd;
    struct hash_elem elem;

    struct file *file;
  };

void 
files_init_files (struct files *f)
{
  f->fd_map = bitmap_create_in_buf (MAX_FILE_COUNT + 2, &f->fd_map_buf, sizeof (f->fd_map_buf));
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
  hash_insert (f->fd_map, file_desc);
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