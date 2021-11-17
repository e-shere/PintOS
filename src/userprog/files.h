#ifndef USERPROG_FILES_H
#define USERPROG_FILES_H

#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "filesys/file.h"
#include "threads/synch.h"

#define MAX_FD_COUNT 128
#define FD_FAILURE -1
#define FD_STDIN 0
#define FD_STDOUT 1

struct files
  {
    struct bitmap *fd_map;
    struct hash fd_table;
    struct lock file_lock;
  };

void files_init_files (struct files *);
int files_open (struct files *, char *);
bool files_is_open (struct files *, int);
struct file *files_get (struct files *, int);
struct files *get_current_files (void);
void files_close (struct files *, int);
void files_destroy_files (struct files *);

#endif /* userprog/files.h */