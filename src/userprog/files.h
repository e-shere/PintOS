#ifndef USERPROG_FILES_H
#define USERPROG_FILES_H

#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "filesys/file.h"

#define MAX_FILE_COUNT 16

struct files
  {
    struct bitmap *fd_map;
    struct hash fd_table;
  };

void files_init_files (struct files *);
int files_open (struct files *, char *);
bool files_is_open (struct files *, int);
struct file *files_get (struct files *, int);
struct files get_current_files ();
void files_close (struct files *, int);

#endif /* userprog/files.h */