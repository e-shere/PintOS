#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/files.h"

/* Information about a user program. */
struct user_prog
  {
    struct guard *parent;
    struct file *executable;       /* The executable file being run. */
    struct files files;            /* Information about file descriptors. */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void process_exit_with_status (int);

#endif /* userprog/process.h */
