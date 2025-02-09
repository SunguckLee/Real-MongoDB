// -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*-
// Copyright (c) 2008, Google Inc.
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// ---
// Author: Sanjay Ghemawat <opensource@google.com>

#include <stdlib.h> // for getenv and strtol
#include "config.h"
#include "common.h"
#include "system-alloc.h"
#include "base/spinlock.h"
#include "getenv_safe.h" // TCMallocGetenvSafe

namespace tcmalloc {

// Define the maximum number of object per classe type to transfer between
// thread and central caches.
static int32 FLAGS_tcmalloc_transfer_num_objects;

static const int32 kDefaultTransferNumObjecs = 512;
static const int32 kTargetTransferBytes = 8 * 1024;

// The init function is provided to explicit initialize the variable value
// from the env. var to avoid C++ global construction that might defer its
// initialization after a malloc/new call.
static inline void InitTCMallocTransferNumObjects()
{
  if (UNLIKELY(FLAGS_tcmalloc_transfer_num_objects == 0)) {
    const char *envval = TCMallocGetenvSafe("TCMALLOC_TRANSFER_NUM_OBJ");
    FLAGS_tcmalloc_transfer_num_objects = !envval ? kDefaultTransferNumObjecs :
      strtol(envval, NULL, 10);
  }
}

// Note: the following only works for "n"s that fit in 32-bits, but
// that is fine since we only use it for small sizes.
static inline int LgFloor(size_t n) {
  int log = 0;
  for (int i = 4; i >= 0; --i) {
    int shift = (1 << i);
    size_t x = n >> shift;
    if (x != 0) {
      n = x;
      log += shift;
    }
  }
  ASSERT(n == 1);
  return log;
}

int AlignmentForSize(size_t size) {
  int alignment = kAlignment;
  if (size > kMaxSize) {
    // Cap alignment at kPageSize for large sizes.
    alignment = kPageSize;
  } else if (size >= 128) {
    // Space wasted due to alignment is at most 1/8, i.e., 12.5%.
    alignment = (1 << LgFloor(size)) / 8;
  } else if (size >= kMinAlign) {
    // We need an alignment of at least 16 bytes to satisfy
    // requirements for some SSE types.
    alignment = kMinAlign;
  }
  // Maximum alignment allowed is page size alignment.
  if (alignment > kPageSize) {
    alignment = kPageSize;
  }
  CHECK_CONDITION(size < kMinAlign || alignment >= kMinAlign);
  CHECK_CONDITION((alignment & (alignment - 1)) == 0);
  return alignment;
}

int SizeMap::NumMoveSize(size_t size) {
  if (size == 0) return 0;
  // Use a min of (8k, 2 count) transfers between thread and central caches.
  int num = kTargetTransferBytes / size;
  if (num < 2) num = 2;

  // Avoid bringing too many objects into small object free lists.
  // If this value is too large:
  // - We waste memory with extra objects sitting in the thread caches.
  // - The central freelist holds its lock for too long while
  //   building a linked list of objects, slowing down the allocations
  //   of other threads.
  // If this value is too small:
  // - We go to the central freelist too often and we have to acquire
  //   its lock each time.
  // This value strikes a balance between the constraints above.
  if (num > FLAGS_tcmalloc_transfer_num_objects)
    num = FLAGS_tcmalloc_transfer_num_objects;

  return num;
}

// Initialize the mapping arrays
void SizeMap::Init() {
  InitTCMallocTransferNumObjects();

  // Do some sanity checking on add_amount[]/shift_amount[]/class_array[]
  if (ClassIndex(0) != 0) {
    Log(kCrash, __FILE__, __LINE__,
        "Invalid class index for size 0", ClassIndex(0));
  }
  if (ClassIndex(kMaxSize) >= sizeof(class_array_)) {
    Log(kCrash, __FILE__, __LINE__,
        "Invalid class index for kMaxSize", ClassIndex(kMaxSize));
  }

  // Compute the size classes we want to use
  int sc = 1;   // Next size class to assign
  size_t potential_merge_sizes[kMaxSize];
  int potential_merge_count = 0;
  int alignment = kAlignment;
  CHECK_CONDITION(kAlignment <= kMinAlign);
  for (size_t size = kAlignment; size <= kMaxSize; size += alignment) {
    alignment = AlignmentForSize(size);
    CHECK_CONDITION((size % alignment) == 0);

    int min_objects_per_span = kTargetTransferBytes / size;
    size_t span_size = 0;
    do {
      span_size += kPageSize;
      // Allocate enough pages so leftover is less than 1/8 of total.
      // This bounds wasted space to at most 12.5%.
      while ((span_size % size) > (span_size >> 3)) {
        span_size += kPageSize;
      }
      // Continue to add pages until there are at least as many objects in
      // the span as are needed when moving objects from the central
      // freelists and spans to the thread caches.
    } while ((span_size / size) < min_objects_per_span);
    const size_t my_pages = span_size >> kPageShift;

    bool merge = (potential_merge_count != 0);
    for (int i = 0; i < potential_merge_count; i++) {
      // See if we can merge this into the previous class(es) without
      // the fragmentation of any of them going over 12.5%.
      int objects_per_span = span_size / size;
      size_t waste = span_size - (potential_merge_sizes[i] * objects_per_span);
      if (waste > (span_size >> 3))
        merge = false;
    }

    if (merge) {
      // Adjust last class to include this size
      class_to_size_[sc-1] = size;
      potential_merge_sizes[potential_merge_count++] = size;
      continue;
    }

    potential_merge_sizes[0] = size;
    potential_merge_count = 1;
    // Add new class
    class_to_pages_[sc] = my_pages;
    class_to_size_[sc] = size;
    sc++;
  }

  if (sc != kNumClasses) {
    Log(kCrash, __FILE__, __LINE__,
        "wrong number of size classes: (found vs. expected )", sc, kNumClasses);
  }

  // Initialize the mapping arrays
  int next_size = 0;
  for (int c = 1; c < kNumClasses; c++) {
    const int max_size_in_class = class_to_size_[c];
    for (int s = next_size; s <= max_size_in_class; s += kAlignment) {
      class_array_[ClassIndex(s)] = c;
    }
    next_size = max_size_in_class + kAlignment;
  }

  // Double-check sizes just to be safe
  for (size_t size = 0; size <= kMaxSize;) {
    const int sc = SizeClass(size);
    if (sc <= 0 || sc >= kNumClasses) {
      Log(kCrash, __FILE__, __LINE__,
          "Bad size class (class, size)", sc, size);
    }
    if (sc > 1 && size <= class_to_size_[sc-1]) {
      Log(kCrash, __FILE__, __LINE__,
          "Allocating unnecessarily large class (class, size)", sc, size);
    }
    const size_t s = class_to_size_[sc];
    if (size > s || s == 0) {
      Log(kCrash, __FILE__, __LINE__,
          "Bad (class, size, requested)", sc, s, size);
    }
    if (size <= kMaxSmallSize) {
      size += 8;
    } else {
      size += 128;
    }
  }

  // Initialize the num_objects_to_move array.
  for (size_t cl = 1; cl  < kNumClasses; ++cl) {
    num_objects_to_move_[cl] = NumMoveSize(ByteSizeForClass(cl));
  }
}

// Metadata allocator -- keeps stats about how many bytes allocated.
static uint64_t metadata_system_bytes_ = 0;
static const size_t kMetadataAllocChunkSize = 8*1024*1024;
// As ThreadCache objects are allocated with MetaDataAlloc, and also
// CACHELINE_ALIGNED, we must use the same alignment as TCMalloc_SystemAlloc.
static const size_t kMetadataAllignment = sizeof(MemoryAligner);

static char *metadata_chunk_alloc_;
static size_t metadata_chunk_avail_;

static SpinLock metadata_alloc_lock(SpinLock::LINKER_INITIALIZED);

void* MetaDataAlloc(size_t bytes) {
  if (bytes >= kMetadataAllocChunkSize) {
    void *rv = TCMalloc_SystemAlloc(bytes,
                                    NULL, kMetadataAllignment);
    if (rv != NULL) {
      metadata_system_bytes_ += bytes;
    }
    return rv;
  }

  SpinLockHolder h(&metadata_alloc_lock);

  // the following works by essentially turning address to integer of
  // log_2 kMetadataAllignment size and negating it. I.e. negated
  // value + original value gets 0 and that's what we want modulo
  // kMetadataAllignment. Note, we negate before masking higher bits
  // off, otherwise we'd have to mask them off after negation anyways.
  intptr_t alignment = -reinterpret_cast<intptr_t>(metadata_chunk_alloc_) & (kMetadataAllignment-1);

  if (metadata_chunk_avail_ < bytes + alignment) {
    size_t real_size;
    void *ptr = TCMalloc_SystemAlloc(kMetadataAllocChunkSize,
                                     &real_size, kMetadataAllignment);
    if (ptr == NULL) {
      return NULL;
    }

    metadata_chunk_alloc_ = static_cast<char *>(ptr);
    metadata_chunk_avail_ = real_size;

    alignment = 0;
  }

  void *rv = static_cast<void *>(metadata_chunk_alloc_ + alignment);
  bytes += alignment;
  metadata_chunk_alloc_ += bytes;
  metadata_chunk_avail_ -= bytes;
  metadata_system_bytes_ += bytes;
  return rv;
}

uint64_t metadata_system_bytes() { return metadata_system_bytes_; }

}  // namespace tcmalloc
