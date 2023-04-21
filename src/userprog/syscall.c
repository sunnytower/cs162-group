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
#include "lib/float.h"
static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  lock_init(&file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void verify_vaddr(uint8_t* vaddr, size_t size);
// static void verify_arg_vaddr(uint8_t* vaddr);
static void verify_string(const char* str);

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  verify_vaddr(args, 4);

  struct process* current = thread_current()->pcb;
  /* validate pointer */
  switch (args[0]) {
    case SYS_READ:
    case SYS_WRITE:
    case SYS_PT_CREATE:
      verify_vaddr(&args[3], 4);
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_SEMA_INIT:
      verify_vaddr(&args[2], 4);
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_PRACTICE:
    case SYS_COMPUTE_E:
    case SYS_PT_JOIN:
    case SYS_LOCK_INIT:
    case SYS_LOCK_ACQUIRE:
    case SYS_LOCK_RELEASE:
    case SYS_SEMA_DOWN:
    case SYS_SEMA_UP:
      verify_vaddr(&args[1], 4);
    case SYS_HALT:
    case SYS_PT_EXIT:
    case SYS_GET_TID:
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
      verify_string(args[1]);
      lock_acquire(&file_lock);
      f->eax = process_execute(args[1]);
      lock_release(&file_lock);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      verify_string(args[1]);
      lock_acquire(&file_lock);
      f->eax = filesys_create(args[1], args[2]);
      lock_release(&file_lock);
      break;
    case SYS_REMOVE:
      verify_string(args[1]);
      lock_acquire(&file_lock);
      f->eax = filesys_remove(args[1]);
      lock_release(&file_lock);
      break;
    case SYS_OPEN: {
      verify_string(args[1]);
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
        f->eax = current->next_fd;
        current->next_fd++;
        if (strcmp((const char*)args[1], current->process_name) == 0) {
          file_deny_write(fp);
        }
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
      verify_vaddr((void*)args[2], args[3]);
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
      verify_vaddr((void*)args[2], args[3]);
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
      struct list* files = &(current->open_files);
      for (struct list_elem* iter = list_begin(files); iter != list_end(files);
           iter = list_next(iter)) {
        struct file_info* info = list_entry(iter, struct file_info, elem);
        if (info->fd == (int)args[1]) {
          file_close(info->fp);
          list_remove(iter);
          free(info);
          break;
        }
      }
      lock_release(&file_lock);
      break;
    }
    case SYS_COMPUTE_E:
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_PT_CREATE:
      f->eax = pthread_execute(args[1], args[2], args[3]);
      break;
    case SYS_PT_JOIN:
      f->eax = pthread_join(args[1]);
      break;
    case SYS_PT_EXIT:
      if (thread_current() == current->main_thread)
        pthread_exit_main();
      else
        pthread_exit();
      break;
    default:
      break;
  }
}

static inline bool valid_vaddr(uint8_t* vaddr) {
  uint32_t* pagedir = thread_current()->pcb->pagedir;
  return vaddr != NULL && is_user_vaddr(vaddr) && pagedir_get_page(pagedir, vaddr) != NULL;
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