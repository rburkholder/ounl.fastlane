# ounl.fastlane/AppFastLane (wt app)
cmake_minimum_required (VERSION 3.13)

project (AppFastLane)

add_subdirectory(bpf/kernel)  # bpf kernel modules

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_COMPILER_ARCHITECTURE_ID, "x64")
#set(CMAKE_EXE_LINKER_FLAGS "--trace --verbose")
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(Boost_ARCHITECTURE "-x64")
#set(BOOST_LIBRARYDIR "/usr/local/lib")
set(BOOST_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(BOOST_USE_STATIC_RUNTIME OFF)
#set(Boost_DEBUG 1)
#set(Boost_REALPATH ON)
#set(BOOST_ROOT "/usr/local")
#set(Boost_DETAILED_FAILURE_MSG ON)
set(BOOST_INCLUDEDIR "/usr/local/include/boost")

find_package(Boost 1.69.0 REQUIRED COMPONENTS system log log_setup program_options)

#message("boost lib: ${Boost_LIBRARIES}")

set(SRC_LINUX /usr/src/linux-4.19.39)

set(
  file_h
    log_syslog.h
    AppManager.h
    AppFastLane.h
    Server.h
    Model1.h
    bpf/user/RawSocket.h
    bpf/user/SockStats.h
    bpf/user/XdpFlow.h
    netlink/interface.h
  )

set(
  file_c
    ${SRC_LINUX}/samples/bpf/bpf_load.c
  )

SET_SOURCE_FILES_PROPERTIES( ${file_c} PROPERTIES LANGUAGE C )

set(
  file_cpp
    log_syslog_builtin.cpp
    log_syslog_native.cpp
    asio_ssl.cpp
    AppManager.cpp
    AppFastLane.cpp
    Server.cpp
    main.cpp
    Model1.cpp
    bpf/user/RawSocket.cpp
    bpf/user/SockStats.cpp
    bpf/user/XdpFlow.cpp
    netlink/interface.cpp
  )

add_executable( 
  ${PROJECT_NAME}
    ${file_h}
    ${file_cpp}
    ${file_c}
  )

target_compile_definitions(${PROJECT_NAME} PUBLIC BOOST_LOG_DYN_LINK BOOST_ASIO_SEPARATE_COMPILATION )

target_include_directories(
  ${PROJECT_NAME} PUBLIC 
    ".."
    ${SRC_LINUX}
    ${SRC_LINUX}/include/uapi
    ${SRC_LINUX}/include
    # asm/linkage.h
    ${SRC_LINUX}/arch/x86/include/uapi
    # unistd_64_x32.h
#    ${SRC_LINUX}/arch/x86/include/generated
    # asm-generic/percpu.h

    // lastest netlink instead of apt installed headers
    /usr/local/include/libnl3

#    /usr/src/linux-headers-4.19.0-5-common/arch/x86/include
#    /usr/src/linux-headers-4.19.0-5-common/include/uapi
#    /usr/src/linux-headers-4.19.0-5-common/arch/x86/include
#    ${SRC_LINUX}/tools/lib/bpf
#    ${SRC_LINUX}/tools/lib

#   asm-generic/barrier.h    
#    ${SRC_LINUX}/tools/include
#    ${SRC_LINUX}/tools/perf
  )

target_link_directories(
  ${PROJECT_NAME} PUBLIC 
    /usr/local/lib
    ${SRC_LINUX}/tools/lib/bpf
  )

target_link_libraries(
  ${PROJECT_NAME}
    wt
    wthttp
    pthread
    ${Boost_LIBRARIES}
    crypto
    ssl
    bpf
    elf
    nl-3
    nl-route-3
  )  

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

# https://cmake.org/cmake/help/v3.4/manual/cmake-properties.7.html#target-properties
# https://stackoverflow.com/questions/tagged/cmake?sort=votes&pagesize=50
# https://github.com/Kitware/CMake/blob/master/Modules/FindBoost.cmake
# https://cmake.org/cmake/help/git-master/module/FindBoost.html

#target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
#add_definitions(${Boost_LIB_DIAGNOSTIC_DEFINITIONS})
#target_include_directories(${PROJECT_NAME} PUBLIC ".." ${Boost_INCLUDE_DIR})
#include_directories(".." ${Boost_INCLUDE_DIR})  
#rm add_link_options( "--trace" )
#target_link_options( ${PROJECT_NAME} PUBLIC "--verbose" "--trace" "--stats")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --verbose --trace --stats")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --verbose --trace")
#set( CMAKE_EXPORT_COMPILE_COMMANDS ON )

#SET_TARGET_PROPERTIES(${PROJECT} PROPERTIES LINK_FLAGS "--verbose --trace")
#SET_TARGET_PROPERTIES(${PROJECT} PROPERTIES COMPILE_FLAGS "-DBOOST_LOG_DYN_LINK" )
