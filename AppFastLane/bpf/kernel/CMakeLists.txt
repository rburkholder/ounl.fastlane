# ounl.fastlane/AppFastLane/bpf/kernel (bpf kernel load modules)
cmake_minimum_required (VERSION 3.13)

project(bpf_kernel)

add_library(
  sock_stats OBJECT 
  sock_stats.c
  )

target_include_directories(
  sock_stats PUBLIC 
  /usr/include/x86_64-linux-gnu
  /usr/src/linux-4.19.39
  /usr/src/linux-headers-4.19.0-5-common/include
  )
  
add_library(
  xdp_flow OBJECT 
  xdp_flow.c
  )
  
target_include_directories(
  xdp_flow PUBLIC
  /usr/src/linux-4.19.39
  /usr/src/linux-4.19.39/include/uapi
  /usr/src/linux-4.19.39/include
  /usr/src/linux-4.19.39/arch/x86/indclude/uapi
  /usr/include/x86_64-linux-gnu
)

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
  
  
