#include "mem_allocator.hpp"

/// +---------------------------------------------+
/// |struct Chunk |     memory                    |
/// +---------------------------------------------+

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#define OVERHEAD (sizeof(Chunk))

namespace {
inline size_t ROUND_TO_8(size_t value) {
    return (value + 7) & ~(0x7);
}
} // namespace

size_t Chunk::usable_length() const {
    return m_len - OVERHEAD;
}

bool Chunk::is_last(MemoryManagerInternal* memgr) const {
    uintptr_t end_address = memgr->capacity() + memgr->base_address();
    uintptr_t cur_chunk_end_address = m_address + m_len;
    return cur_chunk_end_address >= end_address;
}

bool Chunk::is_first(MemoryManagerInternal* memgr) const {
    return m_address == memgr->base_address();
}

/// Split current chunk into 2: `this` contain `mod_len` bytes (this includes overhead) and return the remainder
///
/// #Arguments:
///
/// - `memgr` the memory manager
/// - `mod_len` includes the user length + any overhead for bookkeeping
///
/// #Return:
///
/// This function will fail if the remainder does not have at least `2 x OVERHEAD` bytes
/// otherwise it returns the chunk holding the remainder bytes and marked as "free"
Chunk* Chunk::split(MemoryManagerInternal* memgr, size_t mod_len) {
    // in order to be able to split, we need at least mod_len + 2 x OVERHEAD
    size_t new_len = mod_len;
    size_t min_for_split = 2 * OVERHEAD;
    bool can_split = (m_len >= (new_len + min_for_split));
    if (!can_split) {
        return nullptr;
    }

    Chunk* new_chunk = reinterpret_cast<Chunk*>(address() + new_len);
    new_chunk->m_prev_len = new_len;
    new_chunk->m_len = m_len - new_len;
    new_chunk->m_address = (uintptr_t)new_chunk;
    new_chunk->set_free(true);
    m_len = new_len;

    auto after = new_chunk->next(memgr);
    if (after) {
        after->m_prev_len = new_chunk->m_len;
    }
    return new_chunk;
}

void Chunk::update_length(MemoryManagerInternal* memgr, size_t newlen) {
    // re-add ourselves
    auto& free_list = memgr->free_chunks();
    if (is_free() && free_list.remove_by_addr(this)) {
        // the update to the length must be done **after** the removal
        m_len = newlen;
        free_list.add(this);
    } else {
        // just update the length
        m_len = newlen;
    }
}

bool Chunk::try_merge_with_next(MemoryManagerInternal* memgr, Chunk** addr) {
    // we can only merge chunks if all 3 conditions below are met
    if (!next(memgr) || !next(memgr)->is_free()) {
        return false;
    }

    auto after = next(memgr);
    *addr = (Chunk*)(after->address());
    update_length(memgr, m_len + after->m_len);

    auto after_after = after->next(memgr);
    if (after_after) {
        after_after->m_prev_len = m_len;
    }
    return true;
}

bool Chunk::try_merge_with_previous(MemoryManagerInternal* memgr) {
    // we can only merge chunks if all 3 conditions below are met
    if (!prev(memgr) || !prev(memgr)->is_free()) {
        return false;
    }

    // Merge this one with the one before it - invalidating "this"
    auto before = prev(memgr);
    before->update_length(memgr, before->m_len + m_len);

    auto after = next(memgr);
    if (after) {
        after->m_prev_len = before->m_len;
    }
    return true;
}

/// FreeChunk
void FreeChunks::add(Chunk* chunk) {
    chunk->set_free(true);
    m_freeList.push_back(chunk);
}

bool FreeChunks::remove_by_addr(Chunk* addr) {
    auto iter = std::find_if(m_freeList.begin(), m_freeList.end(), [addr](const Chunk* c) { return c == addr; });

    if (iter != m_freeList.end()) {
        m_freeList.erase(iter);
        return true;
    }
    return false;
}

Chunk* FreeChunks::take_for_size(size_t real_len) {
    auto match_iter = m_freeList.end();
    Chunk* match = nullptr;
    for (auto iter = m_freeList.begin(); iter != m_freeList.end(); ++iter) {
        auto c = (*iter);
        if (c->length() >= real_len) {
            if (match == nullptr) {
                // first match
                match = c;
                match_iter = iter;
                if (m_searchMethod == SearchMethod::kFirstFit) {
                    // No need to search further
                    break;
                }
            } else {
                // we already got a match - check that it is better than the previous one
                if (c->length() < match->length()) {
                    // the new match is better
                    match = c;
                    match_iter = iter;
                }
            }
        }
    }

    if (match && match_iter != m_freeList.end()) {
        match->set_free(false);
        m_freeList.erase(match_iter);
        return match;
    }
    return nullptr;
}

/// MemoryManager
void MemoryManagerInternal::assign(char* mem, size_t len) {
    // Ensure that the address is 64 bits aligned
    uintptr_t addr = (uintptr_t)mem;
    assert((addr & 0x7) == 0);
    // Ensure that we have enough memory to hold our overhead
    assert(len >= OVERHEAD);
    m_head = reinterpret_cast<Chunk*>(mem);
    m_capacity = len;

    m_head->m_len = len;
    m_head->m_address = addr;
    m_head->m_prev_len = 0;
    m_freeChunks.add(m_head);
}

Chunk* MemoryManagerInternal::find_free_chunk_for(size_t actual_len) {
    // Find
    auto chunk = m_freeChunks.take_for_size(actual_len);
    if (chunk == nullptr) {
        return nullptr;
    }

    auto leftover = chunk->split(this, actual_len);
    if (leftover) {
        m_freeChunks.add(leftover);
    }
    return chunk;
}

void* MemoryManagerInternal::do_alloc(size_t size) {
    // align the length to 64 bit address (least 3 digits should be 1 which is 8)
    size = ROUND_TO_8(size);
    size += OVERHEAD; // the actual length

    Chunk* chunk = find_free_chunk_for(size);
    if (chunk == nullptr) {
        return nullptr;
    }
    return chunk->address() + sizeof(Chunk);
}

void MemoryManagerInternal::do_release(void* mem) {
    Chunk* chunk = reinterpret_cast<Chunk*>((char*)mem - sizeof(Chunk));
    assert(chunk->is_free() == false && "**double free**");
    chunk->set_free(true);

    Chunk* addr = nullptr;
    if (chunk->try_merge_with_next(this, &addr)) {
        // remove addr from the free chunks since it was merged with "chunk"
        m_freeChunks.remove_by_addr(addr);
    }

    if (chunk->try_merge_with_previous(this)) {
        // No need to re-add "chunk" to the free-chunk since it was merged
        // with its predecessor - which was free, i.e. it was already in the
        // free chunks list
        return;
    }

    // Could not merge "chunk" with its predecessor. Re-add it
    m_freeChunks.add(chunk);
}

void* MemoryManagerInternal::do_re_alloc(void* mem, size_t newsize) {
    // keep the user requested size, we will need it later
    size_t user_size = newsize;
    if (mem == nullptr) {
        // same as "alloc"
        return do_alloc(user_size);
    }

    if (newsize == 0) {
        // behaves like "free"
        do_release(mem);
        return nullptr;
    }

    Chunk* chunk = reinterpret_cast<Chunk*>((char*)mem - sizeof(Chunk));
    size_t chunk_orig_len = chunk->length();

    // align the new size + add the required overhead size
    newsize = ROUND_TO_8(newsize) + OVERHEAD;
    assert(!chunk->is_free() && "do_re_alloc called for free block !?");
    if (newsize == chunk->length()) {
        // nothing to be done here
        return mem;
    }

    if (newsize < chunk->length()) {
        // shrinking the memory, try to free the remainder if we can
        auto remainder = chunk->split(this, newsize);
        if (remainder) {
            m_freeChunks.add(remainder);
        }
        return mem;
    } else {
        // First we try to merge the current chunk with the one adjacent to it to increase its capacity
        // we do this until we have enough memory to satisfy the newsize. If we fail, we take the hard path:
        // allocate new chunk, copy over the data and release the old chunk
        Chunk* addr = nullptr;
        size_t merge_success = 0;
        while (true) {
            if (!chunk->try_merge_with_next(this, &addr)) {
                break;
            } else {
                // "addr" was merged into "chunk" - remove it from the free chunks list
                m_freeChunks.remove_by_addr(addr);
            }

            ++merge_success;

            // We managed to extend the memory without moving it, see if we got enough space
            if (chunk->length() >= newsize) {
                // see if we got too much
                auto remainder = chunk->split(this, newsize);
                if (remainder) {
                    m_freeChunks.add(remainder);
                }
                return chunk->address() + sizeof(Chunk);
            }
        }

        // If we got here, it means that we could not extend the current chunk to fit the new length
        // allocate new chunk and copy over the memory (though we might have managed to extend it from
        // its original size). We do not need to reclaim the extended memory this is done by "do_release"
        // bellow.
        //
        // NOTICE: we pass here "user_size" and not "newsize" since "do_alloc" will adjust the size
        void* newmem = do_alloc(user_size);
        if (newmem == nullptr) { // OOM
            if (merge_success > 0) {
                // we managed to extended the original chunk (but not enough), by restoring "chunk" back to its
                // original length
                auto remainder = chunk->split(this, chunk_orig_len);
                if (remainder) {
                    m_freeChunks.add(remainder);
                }
            }
            return nullptr;
        }
        std::memcpy(newmem, mem, chunk->usable_length());
        do_release(mem);
        return newmem;
    }
}

size_t MemoryManagerInternal::do_usable_size(const void* mem) const {
    if (mem == nullptr) {
        return 0;
    }

    const Chunk* chunk = reinterpret_cast<const Chunk*>((const char*)mem - sizeof(Chunk));
    return chunk->usable_length();
}

void* MemoryManagerInternal::do_calloc(size_t nmemb, size_t size) {
    size_t mem_size = nmemb * size;
    void* mem = do_alloc(mem_size);
    if (mem == nullptr) {
        return mem;
    }

    std::memset(mem, 0, mem_size);
    return mem;
}
