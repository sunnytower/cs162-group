#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/synch.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

#define BUFFER_CACHE_SIZE 64
/* buffer cache table implement. */
/* TODO: modified filesys_done() to write back dirty block */
struct buffer_cache_entry {
  /* */
  bool valid;
  /* clock algorithm. */
  bool dirty;
  bool used;
  /* used to count if any thread actively writing or reading. */
  int access_cnt;
  int wait_cnt;
  struct condition cond;
  block_sector_t sector;
  uint8_t buffer_cache[BLOCK_SECTOR_SIZE];
};
static struct lock buffer_cache_lock;
static int clock_head;
static struct buffer_cache_entry buffer_cache_table[BUFFER_CACHE_SIZE];

void buffer_cache_init() {
  lock_init(&buffer_cache_lock);
  clock_head = 0;
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    buffer_cache_table[i].valid = false;
    buffer_cache_table[i].dirty = false;
    buffer_cache_table[i].used = false;
    buffer_cache_table[i].access_cnt = 0;
    buffer_cache_table[i].wait_cnt = 0;
    cond_init(&buffer_cache_table[i].cond);
  }
}

/* return index of table entry need hold the lock */
int buffer_cache_evict() {
  while (true) {
    struct buffer_cache_entry* entry = &buffer_cache_table[clock_head];
    if (entry->access_cnt + entry->wait_cnt == 0) {
      if (entry->used) {
        entry->used = false;
      } else {
        if (entry->dirty) {
          block_write(fs_device, entry->sector, entry->buffer_cache);
          entry->dirty = false;
        }
        int index = clock_head;
        clock_head = (clock_head + 1) % BUFFER_CACHE_SIZE;
        return index;
      }
    }
    clock_head = (clock_head + 1) % BUFFER_CACHE_SIZE;
  }
}

/* load sector into buffer if not exist return index */
int buffer_cache_acquire(block_sector_t sector, bool read) {
  lock_acquire(&buffer_cache_lock);
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    /* find sector */
    struct buffer_cache_entry* entry = &buffer_cache_table[i];
    if (entry->valid && entry->sector == sector) {
      while (entry->access_cnt > 0) {
        entry->wait_cnt++;
        cond_wait(&entry->cond, &buffer_cache_lock);
        entry->wait_cnt--;
      }
      entry->access_cnt++;
      lock_release(&buffer_cache_lock);
      return i;
    }
  }
  int index = buffer_cache_evict();
  buffer_cache_table[index].valid = true;
  buffer_cache_table[index].used = true;
  buffer_cache_table[index].sector = sector;
  buffer_cache_table[index].access_cnt = 1;
  buffer_cache_table[index].wait_cnt = 0;
  lock_release(&buffer_cache_lock);
  if (read) {
    block_read(fs_device, sector, buffer_cache_table[index].buffer_cache);
  }
  return index;
}

void buffer_cache_release(int index) {
  lock_acquire(&buffer_cache_lock);
  struct buffer_cache_entry* entry = &buffer_cache_table[index];
  entry->access_cnt--;
  if (entry->wait_cnt >= 0) {
    cond_signal(&entry->cond, &buffer_cache_lock);
  }
  lock_release(&buffer_cache_lock);
}

void buffer_cache_read(block_sector_t sector, uint8_t* buffer, off_t offset, off_t size) {
  int index = buffer_cache_acquire(sector, true);
  memcpy(buffer, buffer_cache_table[index].buffer_cache + offset, size);
  buffer_cache_release(index);
}

void buffer_cache_write(block_sector_t sector, uint8_t* buffer, off_t offset, off_t size) {
  /* may read the sector first */
  off_t sector_left = BLOCK_SECTOR_SIZE - offset;
  bool read = offset > 0 || size < sector_left;
  int index = buffer_cache_acquire(sector, read);
  memcpy(buffer_cache_table[index].buffer_cache + offset, buffer, size);
  buffer_cache_table[index].dirty = true;
  buffer_cache_release(index);
}
/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  buffer_cache_init();
  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  for (int i = 0; i < BUFFER_CACHE_SIZE; ++i) {
    if (buffer_cache_table[i].valid && buffer_cache_table[i].dirty) {
      block_write(fs_device, buffer_cache_table[i].sector, buffer_cache_table[i].buffer_cache);
    }
  }
    free_map_close(); 
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
