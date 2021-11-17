#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/files.h"

void process_init (void);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Information about a user program. */
struct process
  {
    tid_t tid;                     /* TID of the thread. */
    struct hash_elem process_elem; /* Element for process_table. */

    struct semaphore wait_sema;    /* Used to wait on this thread. */
    struct list_elem child_elem;   /* Element for dead_children. */
    struct list dead_children;     /* Dead children which have not been waited
                                      on. */
    tid_t parent_tid;              /* TID of this thread's parent. */
    int exit_status;               /* Argument passed to exit, or -1 if killed
                                      due to error. Undefined if is_running is
                                      set. */
    bool is_running;               /* Whether this program is still running. */
    
    struct file *executable;       /* The executable file being run. */
    struct files files;            /* Information about file descriptors. */
  };

void process_table_lock (void);
bool process_table_locked (void);
void process_table_unlock (void);

struct process *get_process (tid_t); // Pointer to process with this id

void process_exit_with_status (int);

#endif /* userprog/process.h */
