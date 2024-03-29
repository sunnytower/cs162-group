#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include <list.h>
// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* use for create new thread */
struct load_info {
  char* file_name;
  struct process* parent;
  struct semaphore sema_load;
  bool load_success;
};

struct wait_info {
  pid_t pid;                     /* Child process's pid */
  struct process* child_process; /* Child process */
  int exit_status;               /* Child process's exit status */
  struct semaphore sema_wait;    /* semaphore for wait */
  struct list_elem elem;
};

struct file_info {
  int fd;
  struct file* fp;
  struct list_elem elem;
};
/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  int exit_status;
  struct wait_info* wait_info;
  struct list children;
  struct list open_files;
  int next_fd; /* keep track of what next_fd should be */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

struct file* get_file(int fd);
#endif /* userprog/process.h */
