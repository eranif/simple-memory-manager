cmake_minimum_required(VERSION 3.10)
project(simple-memory-manager)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_CXX_STANDARD 17)

add_library(simple-memory-manager STATIC ${CMAKE_CURRENT_LIST_DIR}/mem_allocator.cpp)
target_include_directories(simple-memory-manager PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(simple-memory-manager PUBLIC absl::btree)

add_subdirectory(submodules/googletest)
add_subdirectory(submodules/abseil)

add_executable(memgr-test ${CMAKE_CURRENT_LIST_DIR}/tests.cpp)
target_link_libraries(memgr-test simple-memory-manager gtest gtest_main)
