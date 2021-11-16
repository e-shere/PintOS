#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/files.h"

void process_init (void);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process
  {
    tid_t tid;
    struct hash_elem process_elem;

    struct semaphore wait_sema;
    struct list_elem child_elem;
    struct list dead_children;
    tid_t parent_tid;
    int exit_status;
    
    struct files files;
  };

static struct process *get_process (tid_t); // Pointer to process with this id

void process_exit_with_status (int);

#endif /* userprog/process.h */
