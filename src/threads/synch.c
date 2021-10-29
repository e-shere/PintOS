/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void sema_test_helper (void *sema_);
static void lock_donate_priority (struct lock *, int);
static list_less_func cond_sema_priority_less;

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      list_push_back (&sema->waiters, &thread_current ()->elem);
      thread_block ();
    }
  sema->value--;
  intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  struct thread *next = NULL;
  if (!list_empty (&sema->waiters))
    {
      struct list_elem *e = list_max (&sema->waiters, 
                                      thread_priority_less, NULL);
      list_remove(e);
      next = list_entry (e, struct thread, elem);
      thread_unblock (next);
    }
  sema->value++;
  intr_set_level (old_level);

  if (next != NULL && next->priority > thread_current ()->priority)
    thread_yield_when_possible ();
}

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
  lock->priority = PRI_MIN;
  sema_init (&lock->priority_sema, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));

  if (thread_mlfqs)
    {
      sema_down (&lock->semaphore);
      lock->holder = thread_current ();
      return;
    }

  sema_down (&lock->priority_sema);

  bool sema_down_success = sema_try_down (&lock->semaphore);

  if (!sema_down_success) 
    {
      thread_current ()->lock_waiting_on = lock;
      lock_donate_priority (lock, thread_get_priority ());
      sema_down (&lock->semaphore);

      lock->priority = (list_empty (&lock->semaphore.waiters))
                       ? PRI_MIN
                       : list_entry (list_max (&lock->semaphore.waiters,
                                              &thread_priority_less, NULL),
                                     struct thread, elem)->priority;

      thread_current ()->lock_waiting_on = NULL;
    }

  lock->holder = thread_current ();

  list_push_back (&thread_current ()->locks_held, &lock->elem);

  sema_up (&lock->priority_sema);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success) 
    {
      lock->holder = thread_current ();
      list_push_back (&thread_current ()->locks_held, &lock->elem);
    }

  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  if (thread_mlfqs)
    {
      lock->holder = NULL;
      sema_up (&lock->semaphore);
      return;
    }

  sema_down (&lock->priority_sema);

  list_remove (&lock->elem);

  /* The next two statements don't need to be synchronised because they only
     affects the current thread, which cannot preempt itself. */
  thread_update_donated_priority (thread_current ());
  thread_update_priority (thread_current ());

  lock->holder = NULL;
  sema_up (&lock->priority_sema);
  sema_up (&lock->semaphore);
}

/* Propagates priority donation through threads until one 
   is found that is not waiting on a lock or we reach a point 
   where the donation does not have an effect because it is too 
   low.
   
   Should only be called if lock->sema->waiters contains or 
   is about to contain a thread whose effective priority is
   "priority" AND lock->priority_sema has already been downed. */
void 
lock_donate_priority (struct lock *lock, int priority) 
{
  if (priority > lock->priority)
    lock->priority = priority;

  struct thread *t = lock->holder;
  
  sema_down (&t->priority_sema);
  sema_up (&lock->priority_sema);
  
  if (t->donated_priority < priority) 
    {
      t->donated_priority = priority;
      thread_update_priority (t);

      struct lock *next_lock = t->lock_waiting_on;
      if (next_lock)
        {
          sema_down (&next_lock->priority_sema);
          sema_up (&t->priority_sema);
          lock_donate_priority (next_lock, priority);
        }
      else
        sema_up (&t->priority_sema);
    }
  else
    sema_up (&t->priority_sema);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* Returns true if the priority of lock a is lower than the priority
   of lock b. (Priority of a lock is the maximum of the effective
   priorities of the threads waiting on it, or PRI_MIN) */
bool
lock_priority_less (const struct list_elem *a,
                    const struct list_elem *b,
                    void *aux UNUSED)
{
  return list_entry (a, struct lock, elem)->priority 
         < list_entry (b, struct lock, elem)->priority;
}

/* One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
  };

/* Compares two semaphores from a condition's waiters list by the
   priorities of the threads waiting on them. The semaphores must have
   exactly one waiting thread each. */
bool
cond_sema_priority_less (const struct list_elem *a,
                         const struct list_elem *b,
                         void *aux UNUSED)
{
  struct semaphore_elem *sema_a = list_entry (a, struct semaphore_elem, elem);
  struct semaphore_elem *sema_b = list_entry (b, struct semaphore_elem, elem);
  struct list_elem *thread_a = list_front (&sema_a->semaphore.waiters);
  struct list_elem *thread_b = list_front (&sema_b->semaphore.waiters);
  return thread_priority_less(thread_a, thread_b, NULL); 
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);
  list_push_back (&cond->waiters, &waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (list_empty (&cond->waiters))
    return;
  struct list_elem *e = list_max (&cond->waiters,
                                  &cond_sema_priority_less, NULL);
  list_remove(e);
  sema_up (&list_entry (e,
           struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
