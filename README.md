# Simple Memory Manager

A memory manager that manages a block of memory. This library does not replaces `libc`'s `malloc` family of methods.
This can be done in 2 ways:


## Explicit

```c++
#include "mem_allocator.hpp"
/// If thread-safety is required, use `MemoryManagerThreaded`
static MemoryManagerSimple mem_mgr;

/// Make sure to initialise the memory manager before you call "my_malloc" etc
inline void InitialiseMemoryManager(size_t memsize) {
    static bool once = true;
    if (once) {
        once = false;
        void* mem = malloc(memsize);
        assert(mem != nullptr && "**fatal error** could not allocate initial memory block!");
        mem_mgr.assign(mem, memsize);
    }
}

#define my_malloc(size) mem_mgr.alloc(size)
#define my_free(mem) mem_mgr.release(mem)
#define my_realloc(mem, newsize) mem_mgr.re_alloc(mem, newsize)
```

## Implicit

Implement `malloc`, `free` et al methods in your code

```c++

#include "mem_allocator.hpp"

// Let the manager manage 20MB
constexpr size_t MEM_SIZE = 64 << 20;

/// If thread-safety is required, use `MemoryManagerThreaded`
static MemoryManagerSimple mem_mgr;

/// Make sure to initialise the memory manager before you call "my_malloc" etc
inline void InitialiseMemoryManager() {
    static bool once = true;
    if (once) {
        once = false;
        void* mem = malloc(MEM_SIZE);
        assert(mem != nullptr && "**fatal error** could not allocate initial memory block!");
        mem_mgr.assign(mem, MEM_SIZE);
    }
}

void* malloc(size_t size) {
    InitialiseMemoryManager();
    return mem_mgr.alloc(size);
}

```

## A note about thread-safety

The class `MemoryManagerThreaded` is a `typedef` for `GenericMemoryManager<std::mutex>`
You can replace the lock with your own lock that implements the `lock` and `unlock` methods

