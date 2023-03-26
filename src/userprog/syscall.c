#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  lock_init(&file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void verify_vaddr(uint8_t* vaddr, size_t size);
static void exit(int status);
// static void verify_arg_vaddr(uint8_t* vaddr);
static void verify_string(const char* str);

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  verify_vaddr(args, 4);

  struct process* current = thread_current()->pcb;
  /* validate pointer */
  switch (args[0]) {
    case SYS_PRACTICE:
      // verify_arg_vaddr(&args[1]);
      break;
    case SYS_HALT:
      break;
    case SYS_EXIT:
      break;
    case SYS_EXEC:
      verify_string(args[1]);
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      verify_string(args[1]);
      break;
    case SYS_REMOVE:
      verify_string(args[1]);
      break;
    case SYS_OPEN:
      verify_string(args[1]);
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      verify_string(args[2]);
      break;
    case SYS_WRITE:
      // verify_arg_vaddr(&args[3]);
      break;
    case SYS_SEEK:
      // verify_arg_vaddr(&args[2]);
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    default:
      break;
  }

  switch (args[0]) {
    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      exit(args[1]);
      break;
    case SYS_EXEC:
      f->eax = process_execute(args[1]);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      lock_acquire(&file_lock);
      f->eax = filesys_create(args[1], args[2]);
      lock_release(&file_lock);
      break;
    case SYS_REMOVE:
      lock_acquire(&file_lock);
      f->eax = filesys_remove(args[1]);
      lock_release(&file_lock);
      break;
    case SYS_OPEN: {
      lock_acquire(&file_lock);
      struct file* fp = filesys_open(args[1]);
      if (fp == NULL) {
        f->eax = -1;
      } else {
        /* save the fp to current thread data structure */
        struct file_info* file_info = malloc(sizeof(struct file_info));
        file_info->fp = fp;
        file_info->fd = current->next_fd;
        list_push_back(&(current->open_files), &(file_info->elem));
        current->next_fd++;
      }
      lock_release(&file_lock);
      break;
    }
    case SYS_FILESIZE: {
      lock_acquire(&file_lock);
      struct file* fp = get_file(args[1]);
      if (fp == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_length(fp);
      }
      lock_release(&file_lock);
      break;
    }
    case SYS_READ: {
      switch (args[1]) {
        case 0: {
          uint8_t* p = (uint8_t*)args[2];
          char c;
          for (unsigned int i = 0; i < args[3]; ++i) {
            *(p++) = c = input_getc();
            if (c == EOF) {
              f->eax = i;
              break;
            }
          }
          f->eax = args[3];
          break;
        }
        case 1:
          f->eax = -1;
          break;
        default: {
          lock_acquire(&file_lock);
          struct file* fp = get_file(args[1]);
          if (fp == NULL) {
            f->eax = -1;
          } else {
            f->eax = file_read(fp, args[2], args[3]);
          }
          lock_release(&file_lock);
          break;
        }
      }
      break;
    }
    case SYS_WRITE: {
      switch (args[1]) {
        case 0:
          f->eax = -1;
          break;
        case 1:
          putbuf((char*)args[2], args[3]);
          f->eax = args[3];
          break;
        default: {
          lock_acquire(&file_lock);
          struct file* fp = get_file(args[1]);
          if (fp == NULL) {
            f->eax = -1;
          } else {
            f->eax = file_write(fp, args[2], args[3]);
          }
          lock_release(&file_lock);
          break;
        }
      }
      break;
    }
    case SYS_SEEK: {
      lock_acquire(&file_lock);
      struct file* fp = get_file(args[1]);
      if (fp != NULL) {
        file_seek(fp, args[2]);
      }
      lock_release(&file_lock);
      break;
    }
    case SYS_TELL: {
      lock_acquire(&file_lock);
      struct file* fp = get_file(args[1]);
      if (fp == NULL) {
        f->eax = -1;
      } else {
        f->eax = file_tell(fp);
      }
      lock_release(&file_lock);
      break;
    }
    case SYS_CLOSE: {
      lock_acquire(&file_lock);
      struct file* fp = get_file(args[1]);
      if (fp != NULL) {
        file_close(fp);
      }
      lock_release(&file_lock);
      break;
    }
    default:
      break;
  }
}

static void exit(int status) {
  thread_current()->pcb->exit_status = status;
  process_exit();
}

static inline bool valid_vaddr(uint8_t* vaddr) {
  uint32_t* pagedir = thread_current()->pcb->pagedir;
  return vaddr != NULL && pagedir_get_page(pagedir, vaddr) != NULL;
}

/* validate size bytes of vaddr */
static void verify_vaddr(uint8_t* vaddr, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    if (!valid_vaddr(vaddr + i)) {
      exit(-1);
    }
  }
}

static void verify_string(const char* str) {
  while (true) {
    if (!valid_vaddr(str))
      exit(-1);
    if (*str == '\0')
      return;
    ++str;
  }
}