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
  
SET (CMAKE_C_COMPILER             "/usr/bin/clang")
#SET (CMAKE_C_FLAGS                "-Wall -std=c99")
SET (CMAKE_C_FLAGS                "-O2 -target bpf")
#SET (CMAKE_C_FLAGS_DEBUG          "-g")
#SET (CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
#SET (CMAKE_C_FLAGS_RELEASE        "-O4 -DNDEBUG")
#SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")

#SET_SOURCE_FILES_PROPERTIES( ${file_c} PROPERTIES LANGUAGE C )
  
 #sudo ln -s /usr/src/linux-4.19.39/tools /usr/local/include/tools
 #sudo ln -s /usr/src/linux-headers-4.19.0-5-common/include/uapi/ /usr/local/include/uapi
 #sudo ln -s /usr/src/linux-headers-4.19.0-5-common/include/linux /usr/local/include/linux
 # in eclipse, properties->index->refresh