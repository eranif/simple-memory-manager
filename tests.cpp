#include "mem_allocator.hpp"

#include "gtest/gtest.h"
#include <cassert>
#include <cstdlib>
#include <random>

namespace {
constexpr size_t OVERHEAD = sizeof(Chunk);
inline size_t round_to_8(size_t value) {
    return (value + 7) & ~(0x7);
}

inline Chunk* to_chunk(void* p) {
    Chunk* chunk = (Chunk*)((char*)p - sizeof(Chunk));
    return chunk;
}

inline size_t fix_size(size_t sz) {
    return OVERHEAD + round_to_8(sz);
}

size_t random_number_in_range(size_t start, size_t end) {
    std::random_device dev;
    std::uniform_int_distribution<std::mt19937::result_type> dist(start, end); // distribution in range
    std::mt19937 rng(dev());
    return dist(rng);
}
} // namespace

class MemoryManagerFixture : public ::testing::TestWithParam<FreeChunks*> {};

TEST_P(MemoryManagerFixture, SimpleAllocate) {
    auto free_list_mgr = GetParam();
    MemoryManagerSimple mem(free_list_mgr);

    char buffer[1024];
    mem.assign(buffer, sizeof(buffer));

    void* p = mem.alloc(1024);
    EXPECT_EQ(p, nullptr);

    p = mem.alloc(100);
    EXPECT_TRUE(p != nullptr);

    Chunk* chunk = to_chunk(p);
    EXPECT_FALSE(chunk->is_free());
    EXPECT_EQ(chunk->length(), fix_size(100));
    EXPECT_EQ(chunk->usable_length(), round_to_8(100));

    mem.release(p);
    EXPECT_TRUE(chunk->is_free());
    EXPECT_EQ(chunk->length(), 1024);
}

TEST_P(MemoryManagerFixture, ManyAllocate) {
    auto free_list_mgr = GetParam();
    MemoryManagerSimple mem(free_list_mgr);

    char buffer[1024];
    mem.assign(buffer, sizeof(buffer));
    std::vector<std::pair<void*, size_t>> pointers;

    constexpr size_t ALLOC_SIZE_BASE = 10;
    for (size_t i = 0; i < 10; ++i) {
        pointers.push_back({ mem.alloc(ALLOC_SIZE_BASE + i), ALLOC_SIZE_BASE + i });
    }
    EXPECT_EQ(pointers.size(), 10);
    for (const auto [p, size] : pointers) {
        EXPECT_TRUE(p != nullptr);
        Chunk* chunk = to_chunk(p);
        EXPECT_EQ(chunk->length(), fix_size(size));
    }

    // Traverse over memory list and collect the chunks directly
    Chunk* ptr = to_chunk(pointers[0].first);
    auto& mem_internal = mem.GetImpl_TEST();
    std::vector<Chunk*> pointers2;
    while (ptr) {
        pointers2.push_back(ptr);
        ptr = ptr->next(&mem_internal);
    }

    // 10 allocated + 1 free (the remainder)
    EXPECT_EQ(pointers2.size(), 11);
    for (size_t i = 0; i < 10; ++i) {
        // the first 10 should be
        Chunk* ptr = pointers2[i];
        EXPECT_FALSE(ptr->is_free());
        EXPECT_EQ(ptr->length(), fix_size(ALLOC_SIZE_BASE + i)) << "Failed at index: " << i;
    }

    Chunk* last = pointers2[10];
    EXPECT_TRUE(last->is_free());

    // Release all pointers in random order
    while (!pointers.empty()) {
        size_t index = random_number_in_range(0, 1000000) % pointers.size();
        mem.release(pointers[index].first);
        pointers.erase(pointers.begin() + index);
    }

    Chunk* chunk = (Chunk*)buffer;
    EXPECT_EQ(chunk->length(), sizeof(buffer));
    EXPECT_TRUE(chunk->is_last(&mem_internal));
}

/// Test case: allocate buffer, immediately realloc it we expect the manager to be able to extend the buffer
/// without copying the data
TEST_P(MemoryManagerFixture, ReAllocateNoCopy) {
    auto free_list_mgr = GetParam();
    MemoryManagerSimple mem(free_list_mgr);
    char buffer[1024];
    mem.assign(buffer, sizeof(buffer));

    void* p = mem.alloc(200);
    memset(p, 'x', 200);
    EXPECT_TRUE(p != nullptr);

    // copy some data
    void* after_realloc = mem.re_alloc(p, 300);
    EXPECT_TRUE(after_realloc != nullptr);
    EXPECT_EQ(after_realloc, p);

    // Make sure that the data was not modified
    char b[200];
    memset(b, 'x', 200);
    EXPECT_EQ(memcmp(after_realloc, b, 200), 0);
}

TEST_P(MemoryManagerFixture, ReAllocateWithCopy) {
    auto free_list_mgr = GetParam();
    MemoryManagerSimple mem(free_list_mgr);
    char buffer[1024];
    mem.assign(buffer, sizeof(buffer));

    void* p = mem.alloc(200);
    memset(p, 'x', 200);
    EXPECT_TRUE(p != nullptr);

    // do another allocate - to make sure that the next call to re_alloc will
    // cause the data to be copied over to the next chunk
    void* p2 = mem.alloc(50);

    // copy some data
    void* after_realloc = mem.re_alloc(p, 300);
    EXPECT_TRUE(after_realloc != nullptr);
    EXPECT_FALSE(after_realloc == p); // new pointer

    // Make sure that the data was not modified
    char b[200];
    memset(b, 'x', 200);
    EXPECT_EQ(memcmp(after_realloc, b, 200), 0);

    // We expect 3 chunks: free, allocated, allocated
    auto& impl = mem.GetImpl_TEST();
    Chunk* chunk = (Chunk*)buffer;
    EXPECT_TRUE(chunk->is_free());
    EXPECT_TRUE(chunk->is_first(&impl));
    EXPECT_EQ(chunk->length(), fix_size(200));

    chunk = chunk->next(&impl);
    EXPECT_FALSE(chunk->is_free());
    EXPECT_EQ(chunk->length(), fix_size(50));

    chunk = chunk->next(&impl);
    EXPECT_FALSE(chunk->is_free());
    EXPECT_EQ(chunk->length(), fix_size(300));
}

TEST_P(MemoryManagerFixture, ReAllocateWithAttemptToExpand) {
    auto free_list_mgr = GetParam();
    MemoryManagerSimple mem(free_list_mgr);
    char buffer[1024];
    mem.assign(buffer, sizeof(buffer));

    void* p = mem.alloc(200);
    memset(p, 'x', 200);
    EXPECT_TRUE(p != nullptr);

    // do another allocate - to make sure that the next call to re_alloc will
    // cause the data to be copied over to the next chunk
    void* p2 = mem.alloc(50);
    void* p3 = mem.alloc(60);

    // Release p2, so "re_alloc" start expanding into p2 area
    // but will fail because it does not have enough to contain 300 bytes
    mem.release(p2);

    // copy some data
    void* after_realloc = mem.re_alloc(p, 300);
    EXPECT_TRUE(after_realloc != nullptr);
    EXPECT_FALSE(after_realloc == p); // new pointer

    // Make sure that the data was not modified
    char b[200];
    memset(b, 'x', 200);
    EXPECT_EQ(memcmp(after_realloc, b, 200), 0);

    // We expect 3 chunks: free, allocated, allocated
    auto& impl = mem.GetImpl_TEST();
    Chunk* chunk = (Chunk*)buffer;
    EXPECT_TRUE(chunk->is_free());
    EXPECT_TRUE(chunk->is_first(&impl));
    // mem before re_alloc:
    // [200 (f) | 50 (f) | 60 (a) | ... ]
    // re_alloc merged the 200 + 50 into new chunk with length: fix_size(200) + fix_size(50)
    // but it it is not enough to hold fix_size(300) so the data is moved after the "60" section
    EXPECT_EQ(chunk->length(), fix_size(200) + fix_size(50));

    chunk = chunk->next(&impl);
    EXPECT_FALSE(chunk->is_free());
    EXPECT_EQ(chunk->length(), fix_size(60));

    chunk = chunk->next(&impl);
    EXPECT_FALSE(chunk->is_free());
    EXPECT_EQ(chunk->length(), fix_size(300));

    chunk = chunk->next(&impl);
    EXPECT_TRUE(chunk->is_free());
    EXPECT_TRUE(chunk->is_last(&impl));
    EXPECT_EQ(chunk->length(), 1024 - (fix_size(200) + fix_size(60) + fix_size(50) + fix_size(300)));
}

TEST_P(MemoryManagerFixture, ReAllocateWithOOM) {
    auto free_list_mgr = GetParam();
    MemoryManagerSimple mem(free_list_mgr);
    char buffer[1024];
    mem.assign(buffer, sizeof(buffer));

    void* p = mem.alloc(200);
    memset(p, 'x', 200);
    EXPECT_TRUE(p != nullptr);

    // do another allocate - to make sure that the next call to re_alloc will
    // cause the data to be copied over to the next chunk
    void* p2 = mem.alloc(50);
    void* p3 = mem.alloc(50);
    void* p4 = mem.alloc(50);

    // Release p2, so "re_alloc" start expanding into p2 area
    // but will fail because it does not have enough to contain 600 bytes
    mem.release(p2);
    mem.release(p3);

    // realloc, this time we should OOM
    void* after_realloc = mem.re_alloc(p, 600);
    EXPECT_EQ(after_realloc, nullptr);

    auto& impl = mem.GetImpl_TEST();
    Chunk* chunk = (Chunk*)buffer;

    // notice that instead of 3 x 50, we have 1 x 100 (free) + 1 x 50 (alloc)
    // [200 (alloc)| 100 (free) | 50 (alloc)| remainder (free)]
    EXPECT_EQ(chunk->length(), fix_size(200));
    EXPECT_FALSE(chunk->is_free());

    chunk = chunk->next(&impl);
    EXPECT_EQ(chunk->length(), 2 * fix_size(50));
    EXPECT_TRUE(chunk->is_free());

    chunk = chunk->next(&impl);
    EXPECT_EQ(chunk->length(), fix_size(50));
    EXPECT_FALSE(chunk->is_free());

    auto remainder = sizeof(buffer) - (fix_size(200) + 3 * fix_size(50));
    chunk = chunk->next(&impl);
    EXPECT_EQ(chunk->length(), remainder);
    EXPECT_TRUE(chunk->is_free());
}

INSTANTIATE_TEST_SUITE_P(MemoryManagerTests,
                         MemoryManagerFixture,
                         ::testing::Values(new SimpleFreeChunks, new BucketFreeChunks));