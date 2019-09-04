cmake_minimum_required(VERSION 3.2.2)
project(flowstat)

set(CMAKE_CXX_STANDARD 11)


find_library(LIB_EBPFFLOW libebpfflow.a  ${CMAKE_SOURCE_DIR}/libebpfflow)

if(NOT LIB_EBPFFLOW)
    message(STATUS "Build libebpfflow.a:")
    execute_process(COMMAND bash -c "cd ${CMAKE_SOURCE_DIR}/libebpfflow && ./autogen.sh && make libebpfflow.a")
    find_library(LIB_EBPFFLOW libebpfflow.a  ${CMAKE_SOURCE_DIR}/libebpfflow)
    if(NOT LIB_EBPFFLOW)
        message(FATAL_ERROR "*** libebpfflow.a library not found ***")
    endif()
endif()

include_directories(${CMAKE_SOURCE_DIR}/libebpfflow)


set(CMAKE_CXX_FLAGS_DEBUG "-pipe -DDEBUG -Wall -ggdb -O0 ${CMAKE_CXX_FLAGS_ALL}")

set(CMAKE_CXX_FLAGS_RELEASE "-pipe -DNDEBUG -Wall -g0 -O2 -s ${CMAKE_CXX_FLAGS_ALL}")

set(SOURCE_FILES main.cpp)

add_executable(flowstat ${SOURCE_FILES})

target_link_libraries(flowstat bcc ${LIB_EBPFFLOW} curl json-c boost_program_options)
