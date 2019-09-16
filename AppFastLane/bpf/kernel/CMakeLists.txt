# ounl.fastlane/AppFastLane/bpf/kernel (bpf kernel load modules)
cmake_minimum_required (VERSION 3.13)

project(bpf_kernel)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(SRC_LINUX /usr/src/linux-5.2.14)

add_library(
  sock_stats OBJECT
  sock_stats.c
  )

target_include_directories(
  sock_stats PRIVATE
    ${SRC_LINUX}/tools/lib
    ${SRC_LINUX}/tools/include
    #  ${SRC_LINUX}/tools/perf
    ${SRC_LINUX}/include/uapi
    ${SRC_LINUX}/include
    ${SRC_LINUX}/tools/testing/selftests/bpf
    /usr/include/x86_64-linux-gnu
    #  ${SRC_LINUX}
    #  ${SRC_LINUX}/arch/x86/include/uapi
    #  ${SRC_LINUX}/arch/x86/include
    #  ${SRC_LINUX}/arch/x86/include/generated
  )

target_compile_definitions(sock_stats PUBLIC __x86_64__ )

add_library(
  xdp_flow OBJECT
  ../map_common.h
  xdp_flow.c
  )

target_include_directories(
  xdp_flow PRIVATE
    ${SRC_LINUX}/tools/lib
    ${SRC_LINUX}/tools/include
  #  ${SRC_LINUX}/tools/perf
    ${SRC_LINUX}/include/uapi
    ${SRC_LINUX}/include
    ${SRC_LINUX}/tools/testing/selftests/bpf
    /usr/include/x86_64-linux-gnu
  #  ${SRC_LINUX}
  #  ${SRC_LINUX}/arch/x86/include/uapi
  #  ${SRC_LINUX}/arch/x86/include
  #  ${SRC_LINUX}/arch/x86/include/generated
)

target_compile_definitions(xdp_flow PUBLIC __x86_64__ )

#
# built to:
# build/cmake.debug.linux.x86_64/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o

SET (CMAKE_C_COMPILER             "/usr/bin/clang")
#SET (CMAKE_C_FLAGS                "-Wall -std=c99")
SET (CMAKE_C_FLAGS                "-O2 -target bpf")
#SET (CMAKE_C_FLAGS_DEBUG          "-g")
#SET (CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
#SET (CMAKE_C_FLAGS_RELEASE        "-O4 -DNDEBUG")
#SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")

#SET_SOURCE_FILES_PROPERTIES( ${file_c} PROPERTIES LANGUAGE C )
