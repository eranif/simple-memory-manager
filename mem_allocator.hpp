#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <unordered_set>

class MemoryManager;
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

    bool is_last(MemoryManager* memgr) const;
    bool is_first(MemoryManager* memgr) const;

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
    inline Chunk* next(MemoryManager* memgr) {
        if (is_last(memgr)) {
            return nullptr;
        }
        char* next_addr = address() + length();
        return reinterpret_cast<Chunk*>(next_addr);
    }

    /// Return the previous chunk in the list, can be nullptr
    inline Chunk* prev(MemoryManager* memgr) {
        if (is_first(memgr)) {
            return nullptr;
        }
        char* prev_addr = address() - previous_length();
        return reinterpret_cast<Chunk*>(prev_addr);
    }

    Chunk* split(MemoryManager* memgr, size_t len);

    /// Try to merge this chunk with the one that comes after it
    /// On success, "addr" contains the address of the merged chunk
    bool try_merge_with_next(MemoryManager* memgr, Chunk** addr);

    /// Try to merge this chunk with the one that comes before it
    bool try_merge_with_previous(MemoryManager* memgr);

    /// Update the chunk's new length. Since we are keeping records based on the
    /// chunk size, we need to update the FreeChunk tree with our new length
    void update_length(MemoryManager* memgr, size_t newlen);
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
    Chunk* take_for_size(size_t requested_len);

private:
    std::multimap<size_t, Chunk*> m_freeChunks;
    std::unordered_set<Chunk*> m_addresses;
};

class MemoryManager {
public:
    MemoryManager() = default;
    ~MemoryManager() = default;
    CLASS_NOT_COPYABLE(MemoryManager);

    /// ===----------------------
    /// Public API calls
    /// ===----------------------

    /// Assign memory to be managed by this class
    void assign(char* mem, size_t len);

    /// Allocate memory for the user
    void* alloc(size_t size);

    /// Re-allocate memory. See "realloc" for details
    void* re_alloc(void* mem, size_t newsize);

    /// Release memory previously allocated by this memory manager
    void release(void* mem);

protected:
    void* do_alloc(size_t size);
    void* do_re_alloc(void* mem, size_t newsize);
    void do_release(void* mem);

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
    Chunk* find_free_chunk_for(size_t user_len);

    Chunk* m_head = nullptr;
    FreeChunks m_freeChunks;
    size_t m_capacity = 0;
};
