#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/files.h"

void process_init (void);

void process_init_children (struct thread *t);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Information about a user program. */
struct user_prog
  {
    struct guard *parent;
    struct file *executable;       /* The executable file being run. */
    struct files files;            /* Information about file descriptors. */
  };

struct child
  {
    tid_t tid;                     /* TID of the child thread. */
    struct hash_elem elem;         /* Element for user_prog.children. */
    struct guard *guard;
  };

struct guard
  {
    struct lock lock;
    struct relationship *relationship;
  };

struct relationship
  {
    int exit_status;
    struct semaphore wait_sema;
  };

void process_table_lock (void);
bool process_table_locked (void);
void process_table_unlock (void);

struct process *get_process (tid_t); // Pointer to process with this id

void process_exit_with_status (int);

#endif /* userprog/process.h */
