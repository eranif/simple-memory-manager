#include "mem_allocator.hpp"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <ostream>

int main(int argc, char** argv) {
    // max
    std::cout << "sizeof(Chunk):" << sizeof(Chunk) << std::endl;
    char* a = (char*)malloc(100);
    strcpy(a, "hello ");
    char* b = (char*)malloc(10);
    a = (char*)realloc(a, 200);

    MemoryManagerThreaded mem;
    char* addr = (char*)malloc(1024);
    mem.assign(addr, 1024);

    {
        // same release order
        void* buffer1 = mem.alloc(100);
        void* buffer2 = mem.alloc(100);
        mem.release(buffer1);
        mem.release(buffer2);
    }
    {
        // reverse release order
        void* buffer1 = mem.alloc(100);
        void* buffer2 = mem.alloc(50);
        void* buffer3 = mem.alloc(100);
        void* buffer4 = mem.alloc(60);
        mem.release(buffer2);
        mem.release(buffer3);
        mem.release(buffer1);
        mem.release(buffer4);
    }

    // TODO: run fuzzer test
    return 0;
}
