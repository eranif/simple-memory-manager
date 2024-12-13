#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <unordered_set>

class MemoryManagerInternal;

/// If SMM_HUGE_ALLOCATIONS=0, allocation are limited to 4GB.
/// Note that this does not affect the managed memory size, i.e. the managed memory
/// size can exceed 4GB, the limitation is *per* single allocation
#if SMM_HUGE_ALLOCATIONS
typedef size_t size_type_t;
#else
typedef uint32_t size_type_t;
#endif

#define IS_ALLOCATED_BIT (((uint64_t)1) << 63)
#define FLAGS_MASK IS_ALLOCATED_BIT

struct Chunk {
    /// The chunk address + extra bits. We use the MSD bit as a marker
    /// to check whether or not this chunk is allocated. This will help
    /// us reduce the OVERHEAD size
    uintptr_t m_address_raw = 0;
    /// The length of this chunk
    size_type_t m_len = 0;
    /// The previous chunk's length
    size_type_t m_prev_len = 0;

    inline bool is_free() const {
        return (m_address_raw & IS_ALLOCATED_BIT) == 0;
    }

    bool is_last(MemoryManagerInternal* memgr) const;
    bool is_first(MemoryManagerInternal* memgr) const;

    inline void set_free(bool b) {
        if (b) {
            m_address_raw &= ~IS_ALLOCATED_BIT;
        } else {
            m_address_raw |= IS_ALLOCATED_BIT;
        }
    }

    /// Return the total memory length
    inline size_type_t length() const {
        return m_len;
    }

    /// The size that is actually usable by the user
    size_type_t usable_length() const;

    inline size_type_t previous_length() const {
        return m_prev_len;
    }

    /// Update the chunk's address while keeping the IS_FREE bit
    void set_address(uintptr_t addr) {
        bool free_chunk = is_free();
        m_address_raw = addr;
        set_free(free_chunk);
    }

    /// Return the address as "char*"
    inline char* address_ptr() const {
        // clear bits used as flags
        uintptr_t address = m_address_raw & ~FLAGS_MASK;
        return (char*)address;
    }

    /// Return the address as "uintptr_t"
    inline uintptr_t address_as_uintptr_t() const {
        // clear bits used as flags
        uintptr_t address = m_address_raw & ~FLAGS_MASK;
        return address;
    }

    /// Return the next chunk in the list, can be nullptr
    inline Chunk* next(MemoryManagerInternal* memgr) {
        if (is_last(memgr)) {
            return nullptr;
        }
        char* next_addr = address_ptr() + length();
        return reinterpret_cast<Chunk*>(next_addr);
    }

    /// Return the previous chunk in the list, can be nullptr
    inline Chunk* prev(MemoryManagerInternal* memgr) {
        if (is_first(memgr)) {
            return nullptr;
        }
        char* prev_addr = address_ptr() - previous_length();
        return reinterpret_cast<Chunk*>(prev_addr);
    }

    Chunk* split(MemoryManagerInternal* memgr, size_type_t len);

    /// Try to merge this chunk with the one that comes after it
    /// On success, "addr" contains the address of the merged chunk
    bool try_merge_with_next(MemoryManagerInternal* memgr, Chunk** addr);

    /// Try to merge this chunk with the one that comes before it
    bool try_merge_with_previous(MemoryManagerInternal* memgr);

    /// Update the chunk's new length. Since we are keeping records based on the
    /// chunk size, we need to update the FreeChunk tree with our new length
    void update_length(MemoryManagerInternal* memgr, size_type_t newlen);
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

    /// Find the best fit for requested_len, if a match is found, remove it
    Chunk* take_for_size(size_type_t requested_len);

private:
    std::multimap<size_type_t, Chunk*> m_freeChunks;
    std::unordered_set<Chunk*> m_addresses;
};

/// Used internally
class MemoryManagerInternal {
public:
    MemoryManagerInternal() = default;
    ~MemoryManagerInternal() = default;
    CLASS_NOT_COPYABLE(MemoryManagerInternal);

    /// Assign memory to be managed by this class
    void assign(char* mem, size_type_t len);

    /// Allocate memory for the user
    void* do_alloc(size_type_t size);

    /// Re-allocate memory. See "realloc" for details
    void* do_re_alloc(void* mem, size_type_t newsize);

    /// Release memory previously allocated by this memory manager
    void do_release(void* mem);

    /// Returns a value no less than the size of the block of allocated memory pointed to by mem.  If mem is NULL, 0
    /// is returned
    size_type_t do_usable_size(const void* mem) const;

    /// Allocates memory for an array of nmemb elements of size bytes each and returns a pointer to the allocated memory
    void* do_calloc(size_type_t nmemb, size_type_t size);

private:
    friend struct Chunk;
    inline uint64_t capacity() const {
        return m_capacity;
    }

    inline uintptr_t base_address() const {
        return (uintptr_t)m_head;
    }
    inline FreeChunks& free_chunks() {
        return m_freeChunks;
    }

    /// Find the best free chunk that can hold the requested memory len
    Chunk* find_free_chunk_for(size_type_t user_len);

    Chunk* m_head = nullptr;
    FreeChunks m_freeChunks;
    uint64_t m_capacity = 0;
};

/// A lock that does nothing
class NoopLock {
    inline void lock() {
    }
    inline void unlock() {
    }
};

template <class LOCK>
class GenericMemoryManager {
public:
    /// Assign memory to be managed by this class
    void assign(char* mem, size_type_t len) {
        std::lock_guard lk{ m_lock };
        m_impl.assign(mem, len);
    }

    /// Allocate memory for the user
    void* alloc(size_type_t size) {
        std::lock_guard lk{ m_lock };
        return m_impl.do_alloc(size);
    }

    /// Re-allocate memory. See "realloc" for details
    void* re_alloc(void* mem, size_type_t newsize) {
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
    size_type_t usable_size(const void* mem) const {
        return m_impl.do_usable_size(mem);
    }

    /// Allocates memory for an array of `elements_count` elements of `element_size` bytes each and returns
    /// a pointer to the allocated memory
    void* calloc(size_type_t elements_count, size_type_t element_size) {
        std::lock_guard lk{ m_lock };
        return m_impl.do_calloc(elements_count, element_size);
    }

private:
    MemoryManagerInternal m_impl;
    LOCK m_lock;
};

// Non thread-safe version
typedef GenericMemoryManager<NoopLock> MemoryManagerSimple;

/// Thread safe version, using mutex
typedef GenericMemoryManager<std::mutex> MemoryManagerThreaded;
