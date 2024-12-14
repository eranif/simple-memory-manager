#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>

class MemoryManagerInternal;
struct Chunk {
    /// The chunk address
    uintptr_t m_address = 0;
    /// The length of this chunk
    size_t m_len = 0;
    /// The previous chunk's length
    size_t m_prev_len = 0;
    /// Is free?
    bool m_is_free = true;

    inline bool is_free() const {
        return m_is_free;
    }

    bool is_last(MemoryManagerInternal* memgr) const;
    bool is_first(MemoryManagerInternal* memgr) const;

    inline void set_free(bool b) {
        m_is_free = b;
    }

    /// Return the total memory length
    inline size_t length() const {
        return m_len;
    }

    /// The size that is actually usable by the user
    size_t usable_length() const;

    inline size_t previous_length() const {
        return m_prev_len;
    }

    /// Given the base address, return the address of this chunk
    inline char* address() const {
        return (char*)m_address;
    }

    /// Return the next chunk in the list, can be nullptr
    inline Chunk* next(MemoryManagerInternal* memgr) {
        if (is_last(memgr)) {
            return nullptr;
        }
        char* next_addr = address() + length();
        return reinterpret_cast<Chunk*>(next_addr);
    }

    /// Return the previous chunk in the list, can be nullptr
    inline Chunk* prev(MemoryManagerInternal* memgr) {
        if (is_first(memgr)) {
            return nullptr;
        }
        char* prev_addr = address() - previous_length();
        return reinterpret_cast<Chunk*>(prev_addr);
    }

    Chunk* split(MemoryManagerInternal* memgr, size_t mod_len);

    /// Try to merge this chunk with the one that comes after it
    /// On success, "addr" contains the address of the merged chunk
    bool try_merge_with_next(MemoryManagerInternal* memgr, Chunk** addr);

    /// Try to merge this chunk with the one that comes before it
    bool try_merge_with_previous(MemoryManagerInternal* memgr);

    /// Update the chunk's new length. Since we are keeping records based on the
    /// chunk size, we need to update the FreeChunk tree with our new length
    void update_length(MemoryManagerInternal* memgr, size_t newlen);
};

#define CLASS_NOT_COPYABLE(ClassName)               \
    ClassName(const ClassName&) = delete;           \
    ClassName& operator=(const ClassName&) = delete

class FreeChunks {
public:
    FreeChunks() = default;
    ~FreeChunks() = default;
    CLASS_NOT_COPYABLE(FreeChunks);

    /// Add chunk to the list of free chunks
    void add(Chunk* chunk);

    /// Delete addr from the free chunks
    bool remove_by_addr(Chunk* addr);

    /// Find the best fit for requested_len, if a match is found, remove it.
    /// `requested_len` should contain all the overhead needed + alignment
    Chunk* take_for_size(size_t requested_len);

private:
    std::list<Chunk*> m_freeList;
};

/// Used internally
class MemoryManagerInternal {
public:
    MemoryManagerInternal() = default;
    ~MemoryManagerInternal() = default;
    CLASS_NOT_COPYABLE(MemoryManagerInternal);

    /// Assign memory to be managed by this class
    void assign(char* mem, size_t len);

    /// Allocate memory for the user
    void* do_alloc(size_t size);

    /// Re-allocate memory. See "realloc" for details
    void* do_re_alloc(void* mem, size_t newsize);

    /// Release memory previously allocated by this memory manager
    void do_release(void* mem);

    /// Returns a value no less than the size of the block of allocated memory pointed to by mem.  If mem is NULL, 0
    /// is returned
    size_t do_usable_size(const void* mem) const;

    /// Allocates memory for an array of nmemb elements of size bytes each and returns a pointer to the allocated memory
    void* do_calloc(size_t nmemb, size_t size);

private:
    friend struct Chunk;
    inline size_t capacity() const {
        return m_capacity;
    }

    inline uintptr_t base_address() const {
        return (uintptr_t)m_head;
    }
    inline FreeChunks& free_chunks() {
        return m_freeChunks;
    }

    /// Find the best free chunk that can hold the requested memory len
    /// "actual_len" is the fixed size after adding header size + alignment
    Chunk* find_free_chunk_for(size_t actual_len);

    Chunk* m_head = nullptr;
    FreeChunks m_freeChunks;
    size_t m_capacity = 0;
};

/// A lock that does nothing
class NoopLock {
public:
    inline void lock() {
    }
    inline void unlock() {
    }
};

template <class LOCK>
class GenericMemoryManager {
public:
    /// Assign memory to be managed by this class
    void assign(char* mem, size_t len) {
        std::lock_guard lk{ m_lock };
        m_impl.assign(mem, len);
    }

    /// Allocate memory for the user
    void* alloc(size_t size) {
        std::lock_guard lk{ m_lock };
        return m_impl.do_alloc(size);
    }

    /// Re-allocate memory. See "realloc" for details
    void* re_alloc(void* mem, size_t newsize) {
        std::lock_guard lk{ m_lock };
        return m_impl.do_re_alloc(mem, newsize);
    }

    /// Release memory previously allocated by this memory manager
    void release(void* mem) {
        std::lock_guard lk{ m_lock };
        m_impl.do_release(mem);
    }

    /// Returns a value no less than the size of the block of allocated memory pointed to by mem.  If mem is NULL, 0
    /// is returned. No lock is required here as we are working directly on the memory without changing the manager
    size_t usable_size(const void* mem) const {
        return m_impl.do_usable_size(mem);
    }

    /// Allocates memory for an array of `elements_count` elements of `element_size` bytes each and returns
    /// a pointer to the allocated memory
    void* calloc(size_t elements_count, size_t element_size) {
        std::lock_guard lk{ m_lock };
        return m_impl.do_calloc(elements_count, element_size);
    }

    /// For testing purposes, do not use this in production code
    MemoryManagerInternal& GetImpl_TEST() {
        return m_impl;
    }

private:
    MemoryManagerInternal m_impl;
    LOCK m_lock;
};

// Non thread-safe version
typedef GenericMemoryManager<NoopLock> MemoryManagerSimple;

/// Thread safe version, using mutex
typedef GenericMemoryManager<std::mutex> MemoryManagerThreaded;
