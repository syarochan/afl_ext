/*
   american fuzzy lop - error-checking, memory-zeroing alloc routines
   ------------------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014, 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This allocator is not designed to resist malicious attackers (the canaries
   are small and predictable), but provides a robust and portable way to detect
   use-after-free, off-by-one writes, stale pointers, and so on.

 */

#ifndef _HAVE_ALLOC_INL_H
#define _HAVE_ALLOC_INL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "types.h"
#include "debug.h"
/* User-facing macro to sprintf() to a dynamically allocated buffer. */

#define alloc_printf(_str...) ({ \
    u8* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

/* Macro to enforce allocation limits as a last-resort defense against
   integer overflows. */

#define ALLOC_CHECK_SIZE(_s) do { \
    if ((_s) > MAX_ALLOC) \
      ABORT("Bad alloc request: %u bytes", (_s)); \
  } while (0)

/* Macro to check malloc() failures and the like. */

#define ALLOC_CHECK_RESULT(_r, _s) do { \
    if (!(_r)) \
      ABORT("Out of memory: can't allocate %u bytes", (_s)); \
  } while (0)

/* Magic tokens used to mark used / freed chunks. */
/* Positions of guard tokens in relation to the user-visible pointer. */

#define ALLOC_C1(_ptr)  (((u64*)(_ptr))[-2])
#define ALLOC_S(_ptr)   (((u64*)(_ptr))[-1])
#define canary_num(_num) ({ \
      u64 _tmp = (u64)_num; \
    if ((u64)_tmp % 8 != 0) _tmp += 8; \
      _tmp;\
      })

#define ALLOC_C2(_ptr)  (((u64*)(_ptr))[canary_num(ALLOC_S(_ptr)) / 8]) 

#define ALLOC_OFF_HEAD  16
#define ALLOC_OFF_TOTAL (ALLOC_OFF_HEAD + 1)
#define HEAP_CANARY_SIZE 8                         // heap_canary size

// read header
#define HEAD_PTR(_ptr)  (ALLOC_C1(_ptr)  & 0xffffffff) >> 31   // used or freed
#define IDX_PTR(_ptr) (ALLOC_C1(_ptr) & (0x7ff << 20)) >> 20   // index
#define LIST_PTR(_ptr) (ALLOC_C1(_ptr) & (0xff << 12)) >> 12   // fisrt_list_index
#define LIST_IDX_PTR(_ptr) (ALLOC_C1(_ptr) & (0xff << 4)) >> 4 // second_list_index

// write header
#define CLEAR_SET(_ptr) (ALLOC_C1(_ptr) & ~(0xffffffff))
#define USED_SET(_ptr) (ALLOC_C1(_ptr)  | (1 << 31))
#define FREED_SET(_ptr) (ALLOC_C1(_ptr)  & ~(1 << 31))
#define IDX_SET(_ptr, index) (ALLOC_C1(_ptr) & ~(0x7ff << 20)) | (index << 20)
#define LIST_SET(_ptr, list) (ALLOC_C1(_ptr) & ~(0xff << 12)) | (list << 12)
#define LIST_IDX_SET(_ptr, list_idx) (ALLOC_C1(_ptr) & ~(0xff << 4)) | (list_idx << 4)

/* Allocator increments for ck_realloc_block(). */

#define ALLOC_BLK_INC    256

/* Sanity-checking macros for pointers. */

#define CHECK_PTR(_p) do { \
    if (_p) { \
      if (HEAD_PTR(_p) ^ 1) {\
        if (HEAD_PTR(_p) == 0) \
          ABORT("Use after free."); \
        else ABORT("Corrupted head alloc canary."); \
      } \
       if(check_heap_canary(_p))                    \
         ABORT("Corrupted tail alloc canary."); \
    } \
  } while (0)

#define CHECK_PTR_EXPR(_p) ({ \
    typeof (_p) _tmp = (_p); \
    CHECK_PTR(_tmp); \
    _tmp; \
  })

/* Allocate a buffer, explicitly not zeroing it. Returns NULL for zero-sized
   requests. */

struct free_list{
   u16 index;
   u8 list_idx_1;
   u8 list_idx_2;
   struct free_list * fd;
};

struct list_canary{
	u32 index;                      // heap_canary index 0 ~ 2046
   u32 list_idx;                    // second list index
	u32 next;                       // next list
	u32 flag;                       // init:0, not yet:1
	u64 * list[256];                // heap_canary_ptr
   struct free_list * free_list;   // free heap canary list
};

struct list_canary list_s = {0, 0, 0, 0, {0}, 0};

static inline u32 store_heap_canary(u64 heap_canary, void* ptr ,u32 size){
	u64 * victim = 0;
   u64 * victim_list = 0;
   struct free_list * f_list = list_s.free_list;
   u32 header = 0;

	if(!list_s.flag){
		if(!(list_s.list[0] = (u64*)malloc(256 * 8)))
         ABORT("BAD ALLOC MEMORY");
		memset(list_s.list[0], 0x0, 256 * 8);
      victim_list = list_s.list[0];
      if(!(victim_list[0] = (u64)malloc(2047 * 8)))
         ABORT("BAD ALLOC MEMORY");
      memset((u64*)victim_list[0], 0x0, 2047 * 8);
      list_s.flag = 1;
   }
   else if(list_s.index == 2047){
      list_s.index = 0;
      list_s.list_idx++;
      if(list_s.list_idx < 256){
         victim_list = list_s.list[list_s.next];
         if(!(victim_list[list_s.list_idx] = (u64)malloc(2047 * 8)))
            ABORT("BAD ALLOC MEMORY");
         memset((u64*)victim_list[list_s.list_idx], 0x0, 2047 * 8);
      }
      if(list_s.list_idx == 256 && list_s.next < 255){
         list_s.list_idx = 0;
         list_s.next++;
         if(!(list_s.list[list_s.next] = (u64*)malloc(256 * 8)))
            ABORT("BAD ALLOC MEMORY");
         memset(list_s.list[list_s.next], 0x0, 256 * 8);
         victim_list = (u64*)list_s.list[list_s.next];
         if(!(victim_list[list_s.list_idx] = (u64)malloc(2047 * 8)))
            ABORT("BAD ALLOC MEMORY");
         memset((u64*)victim_list[list_s.list_idx], 0x0, 2047 * 8);
      }
   }
   else if(list_s.next == 256 && list_s.free_list == NULL){
      ABORT("heap canary list is full !!");
   }
   // pick up free heap canary list
   if(list_s.free_list > 0){
      // set next free canary list and set heap canary
      list_s.free_list = f_list->fd;
      victim_list = list_s.list[f_list->list_idx_1]; 
      victim = (u64*)victim_list[f_list->list_idx_2];
      victim[f_list->index] = heap_canary;
      // set header
      ALLOC_C1(ptr) = CLEAR_SET(ptr);
      header =  LIST_IDX_SET(ptr, f_list->list_idx_2);
      header += IDX_SET(ptr, f_list->index);
      header += LIST_SET(ptr, f_list->list_idx_1);
      header += USED_SET(ptr);
      ALLOC_C1(ptr) = header;         // header
      ALLOC_S(ptr)  = size;           // user_size
      ALLOC_C2(ptr) = heap_canary;    // heap_canary
      free(f_list);

      return 1;
   }

   while(list_s.index < 2047){
      victim_list = list_s.list[list_s.next];
      victim      = (u64*)victim_list[list_s.list_idx];
      if((u64*)victim[list_s.index] == (u64*)NULL){
         victim[list_s.index] = heap_canary;
         // set header
         ALLOC_C1(ptr) = CLEAR_SET(ptr);
         header = LIST_IDX_SET(ptr, list_s.list_idx);
         header += IDX_SET(ptr, list_s.index);
         header += LIST_SET(ptr, list_s.next);
         header += USED_SET(ptr);
         ALLOC_C1(ptr) = header;
         ALLOC_S(ptr)  = size;           // user_size
         ALLOC_C2(ptr) = heap_canary;    // heap_canary
         list_s.index++;

         return 1;
      }
      list_s.index++;
   }

   return 0;
}

static inline u64 form_heap_canary(){
   int fd;
   u64 buf[8] = {0};

   if( (fd = open("/dev/urandom", O_RDONLY )) == -1 ){
      ABORT("open /dev/urandom is ERROR");
      return 0;
   }
   
   if(!read(fd, buf, 7)){
      ABORT("read /dev/urandom is ERROR");
      return 0;
   }
   
   close(fd);
   
   return buf[0] << 8;
}

static inline u32 check_heap_canary(void* ptr){
   u64 heap_canary           = ALLOC_C2(ptr);
   u32 victim_index          = IDX_PTR(ptr);
   u32 victim_1st_list_index = LIST_PTR(ptr);
   u32 victim_2nd_list_index = LIST_IDX_PTR(ptr);
   u64 * victim_list           = list_s.list[victim_1st_list_index];
   u64 * victim                = (u64*)victim_list[victim_2nd_list_index];

      if(victim[victim_index] != heap_canary){
         ABORT("Heap Overflow detected !!");
         return 1;
      }

   return 0;
}

static inline u32 free_heap_canary(void* ptr){
   u32 victim_index            = IDX_PTR(ptr);
   u32 victim_1st_list_index   = LIST_PTR(ptr);
   u32 victim_2nd_list_index   = LIST_IDX_PTR(ptr);
   u64 * victim_list           = list_s.list[victim_1st_list_index];
   u64 * victim                = (u64*)victim_list[victim_2nd_list_index];
   struct free_list * f_victim = list_s.free_list;
   struct free_list * f_list   = (struct free_list *)malloc(sizeof(struct free_list));

   if(!f_list)
      ABORT("BAD ALLOC MEMORY");
   
   memset(f_list, 0, sizeof(struct free_list));
   victim[victim_index] = (u64)NULL; // heap canary init

   // cache free list memory rule is queue
   while(f_victim){
      if(!f_victim->fd){
         f_victim->fd = f_list;
         break;
      }
      f_victim = f_victim->fd;
   }
   if(!list_s.free_list)
      list_s.free_list = f_list;
   f_list->index      = victim_index;
   f_list->list_idx_1 = victim_1st_list_index;
   f_list->list_idx_2 = victim_2nd_list_index;
   f_list->fd         = NULL;

   return 0;

}

static inline void* DFL_ck_alloc_nozero(u32 size){
	void* ret;
   u64 heap_canary = form_heap_canary();

	if (!size) return NULL;

	ALLOC_CHECK_SIZE(size);
	ret = malloc(size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
   if(!ret)
      ABORT("BAD ALLOC MEMORY");
   memset(ret, 0x0, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
   ALLOC_CHECK_RESULT(ret, size);

	ret += ALLOC_OFF_HEAD; // offset
   if(!store_heap_canary(heap_canary, ret ,size))
      ABORT("store_heap_canary function is ERROR !?");

	return ret;

}

/* Allocate a buffer, returning zeroed memory. */

static inline void* DFL_ck_alloc(u32 size) {

  void* mem;

  if (!size) return NULL;
  mem = DFL_ck_alloc_nozero(size);

  return memset(mem, 0, size);

}

/* Free memory, checking for double free and corrupted heap. When DEBUG_BUILD
   is set, the old memory will be also clobbered with 0xFF. */

static inline void DFL_ck_free(void* mem) {

  if (!mem) return;

  CHECK_PTR(mem);
#ifdef DEBUG_BUILD

  /* Catch pointer issues sooner. */
  memset(mem, 0xFF, ALLOC_S(mem));

#endif /* DEBUG_BUILD */
  ALLOC_C1(mem) = FREED_SET(mem);
  free_heap_canary(mem);
  free(mem - ALLOC_OFF_HEAD);

}

/* Re-allocate a buffer, checking for issues and zeroing any newly-added tail.
   With DEBUG_BUILD, the buffer is always reallocated to a new addresses and the
   old memory is clobbered with 0xFF. */

static inline void* DFL_ck_realloc(void* orig, u32 size) {

  void* ret;
  u32   old_size = 0;
  u64 heap_canary = form_heap_canary();

  if (!size) {

    DFL_ck_free(orig);
    return NULL;

  }

  if (orig) {

    CHECK_PTR(orig);

#ifndef DEBUG_BUILD
    ALLOC_C1(orig) = FREED_SET(orig);
#endif /* !DEBUG_BUILD */

    old_size  = ALLOC_S(orig);
    orig     -= ALLOC_OFF_HEAD;

    ALLOC_CHECK_SIZE(old_size);

  }

  ALLOC_CHECK_SIZE(size);

#ifndef DEBUG_BUILD

  ret = realloc(orig, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
   memset(ret, 0x0, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE );
  ALLOC_CHECK_RESULT(ret, size);

#else

  /* Catch pointer issues sooner: force relocation and make sure that the
     original buffer is wiped. */

  ret = malloc(size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  if(!ret)
     ABORT("BAD ALLOC MEMORY");
   memset(ret,  0x0, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  ALLOC_CHECK_RESULT(ret, size);

  if (orig) {

    memcpy(ret + ALLOC_OFF_HEAD, orig + ALLOC_OFF_HEAD, MIN(size, old_size));
    memset(orig + ALLOC_OFF_HEAD, 0xFF, old_size);

    ALLOC_C1(orig + ALLOC_OFF_HEAD) = FREED_SET(orig + ALLOC_OFF_HEAD);
    free(orig);

  }

#endif /* ^!DEBUG_BUILD */

  ret += ALLOC_OFF_HEAD;

   if(!store_heap_canary(heap_canary, ret ,size))
      ABORT("store_heap_canary function is ERROR !?");

  if (size > old_size)
    memset(ret + old_size, 0, size - old_size);

  return ret;

}


/* Re-allocate a buffer with ALLOC_BLK_INC increments (used to speed up
   repeated small reallocs without complicating the user code). */

static inline void* DFL_ck_realloc_block(void* orig, u32 size) {

#ifndef DEBUG_BUILD

  if (orig) {

    CHECK_PTR(orig);

    if (ALLOC_S(orig) >= size) return orig;

    size += ALLOC_BLK_INC;

  }

#endif /* !DEBUG_BUILD */

  return DFL_ck_realloc(orig, size);

}


/* Create a buffer with a copy of a string. Returns NULL for NULL inputs. */

static inline u8* DFL_ck_strdup(u8* str) {

  void* ret;
  u32   size;
  u64 heap_canary = form_heap_canary();
  
  if (!str) return NULL;

  size = strlen((char*)str) + 1;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  if(!ret)
     ABORT("BAD ALLOC MEMORY");
  memset(ret, 0x0, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  ALLOC_CHECK_RESULT(ret, size);

  ret += ALLOC_OFF_HEAD;

   if(!store_heap_canary(heap_canary, ret ,size))
      ABORT("store_heap_canary function is ERROR !?");

  return memcpy(ret, str, size);

}


/* Create a buffer with a copy of a memory block. Returns NULL for zero-sized
   or NULL inputs. */

static inline void* DFL_ck_memdup(void* mem, u32 size) {

  void* ret;
  u64 heap_canary = form_heap_canary();

  if (!mem || !size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  if(!ret)
     ABORT("BAD ALLOC MEMORY");
  memset(ret, 0x0, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  ALLOC_CHECK_RESULT(ret, size);
  
  ret += ALLOC_OFF_HEAD;

   if(!store_heap_canary(heap_canary, ret ,size))
      ABORT("store_heap_canary function is ERROR !?");

  return memcpy(ret, mem, size);

}


/* Create a buffer with a block of text, appending a NUL terminator at the end.
   Returns NULL for zero-sized or NULL inputs. */

static inline u8* DFL_ck_memdup_str(u8* mem, u32 size) {

  u8* ret;
  u64 heap_canary = form_heap_canary();
  
  if (!mem || !size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE + 1);
  if(!ret)
     ABORT("BAD ALLOC MEMORY");
  memset(ret, 0x0, size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
  ALLOC_CHECK_RESULT(ret, size);
  
  ret += ALLOC_OFF_HEAD;

   if(!store_heap_canary(heap_canary, ret ,size))
      ABORT("store_heap_canary function is ERROR !?");

  memcpy(ret, mem, size);
  ret[size] = 0;

  return ret;

}


#ifndef DEBUG_BUILD

/* In non-debug mode, we just do straightforward aliasing of the above functions
   to user-visible names such as ck_alloc(). */

#define ck_alloc          DFL_ck_alloc
#define ck_alloc_nozero   DFL_ck_alloc_nozero
#define ck_realloc        DFL_ck_realloc
#define ck_realloc_block  DFL_ck_realloc_block
#define ck_strdup         DFL_ck_strdup
#define ck_memdup         DFL_ck_memdup
#define ck_memdup_str     DFL_ck_memdup_str
#define ck_free           DFL_ck_free

#define alloc_report()

#else

/* In debugging mode, we also track allocations to detect memory leaks, and the
   flow goes through one more layer of indirection. */

/* Alloc tracking data structures: */

#define ALLOC_BUCKETS     4096

struct TRK_obj {
  void *ptr;
  char *file, *func;
  u32  line;
};

#ifdef AFL_MAIN

struct TRK_obj* TRK[ALLOC_BUCKETS];
u32 TRK_cnt[ALLOC_BUCKETS];

#  define alloc_report() TRK_report()

#else

extern struct TRK_obj* TRK[ALLOC_BUCKETS];
extern u32 TRK_cnt[ALLOC_BUCKETS];

#  define alloc_report()

#endif /* ^AFL_MAIN */

/* Bucket-assigning function for a given pointer: */

#define TRKH(_ptr) (((((u32)(_ptr)) >> 16) ^ ((u32)(_ptr))) % ALLOC_BUCKETS)


/* Add a new entry to the list of allocated objects. */

static inline void TRK_alloc_buf(void* ptr, const char* file, const char* func,
                                 u32 line) {

  u32 i, bucket;

  if (!ptr) return;

  bucket = TRKH(ptr);

  /* Find a free slot in the list of entries for that bucket. */

  for (i = 0; i < TRK_cnt[bucket]; i++)

    if (!TRK[bucket][i].ptr) {

      TRK[bucket][i].ptr  = ptr;
      TRK[bucket][i].file = (char*)file;
      TRK[bucket][i].func = (char*)func;
      TRK[bucket][i].line = line;
      return;

    }

  /* No space available - allocate more. */

  TRK[bucket] = DFL_ck_realloc_block(TRK[bucket],
    (TRK_cnt[bucket] + 1) * sizeof(struct TRK_obj));

  TRK[bucket][i].ptr  = ptr;
  TRK[bucket][i].file = (char*)file;
  TRK[bucket][i].func = (char*)func;
  TRK[bucket][i].line = line;

  TRK_cnt[bucket]++;

}


/* Remove entry from the list of allocated objects. */

static inline void TRK_free_buf(void* ptr, const char* file, const char* func,
                                u32 line) {

  u32 i, bucket;

  if (!ptr) return;

  bucket = TRKH(ptr);

  /* Find the element on the list... */

  for (i = 0; i < TRK_cnt[bucket]; i++)

    if (TRK[bucket][i].ptr == ptr) {

      TRK[bucket][i].ptr = 0;
      return;

    }

  WARNF("ALLOC: Attempt to free non-allocated memory in %s (%s:%u)",
        func, file, line);

}


/* Do a final report on all non-deallocated objects. */

static inline void TRK_report(void) {

  u32 i, bucket;

  fflush(0);

  for (bucket = 0; bucket < ALLOC_BUCKETS; bucket++)
    for (i = 0; i < TRK_cnt[bucket]; i++)
      if (TRK[bucket][i].ptr)
        WARNF("ALLOC: Memory never freed, created in %s (%s:%u)",
              TRK[bucket][i].func, TRK[bucket][i].file, TRK[bucket][i].line);

}


/* Simple wrappers for non-debugging functions: */

static inline void* TRK_ck_alloc(u32 size, const char* file, const char* func,
                                 u32 line) {

  void* ret = DFL_ck_alloc(size);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}


static inline void* TRK_ck_realloc(void* orig, u32 size, const char* file,
                                   const char* func, u32 line) {

  void* ret = DFL_ck_realloc(orig, size);
  TRK_free_buf(orig, file, func, line);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}


static inline void* TRK_ck_realloc_block(void* orig, u32 size, const char* file,
                                         const char* func, u32 line) {

  void* ret = DFL_ck_realloc_block(orig, size);
  TRK_free_buf(orig, file, func, line);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}


static inline void* TRK_ck_strdup(u8* str, const char* file, const char* func,
                                  u32 line) {

  void* ret = DFL_ck_strdup(str);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}


static inline void* TRK_ck_memdup(void* mem, u32 size, const char* file,
                                  const char* func, u32 line) {

  void* ret = DFL_ck_memdup(mem, size);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}


static inline void* TRK_ck_memdup_str(void* mem, u32 size, const char* file,
                                      const char* func, u32 line) {

  void* ret = DFL_ck_memdup_str(mem, size);
  TRK_alloc_buf(ret, file, func, line);
  return ret;

}


static inline void TRK_ck_free(void* ptr, const char* file,
                                const char* func, u32 line) {

  TRK_free_buf(ptr, file, func, line);
  DFL_ck_free(ptr);

}

/* Aliasing user-facing names to tracking functions: */

#define ck_alloc(_p1) \
  TRK_ck_alloc(_p1, __FILE__, __FUNCTION__, __LINE__)

#define ck_alloc_nozero(_p1) \
  TRK_ck_alloc(_p1, __FILE__, __FUNCTION__, __LINE__)

#define ck_realloc(_p1, _p2) \
  TRK_ck_realloc(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)

#define ck_realloc_block(_p1, _p2) \
  TRK_ck_realloc_block(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)

#define ck_strdup(_p1) \
  TRK_ck_strdup(_p1, __FILE__, __FUNCTION__, __LINE__)

#define ck_memdup(_p1, _p2) \
  TRK_ck_memdup(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)

#define ck_memdup_str(_p1, _p2) \
  TRK_ck_memdup_str(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)

#define ck_free(_p1) \
  TRK_ck_free(_p1, __FILE__, __FUNCTION__, __LINE__)

#endif /* ^!DEBUG_BUILD */

#endif /* ! _HAVE_ALLOC_INL_H */
