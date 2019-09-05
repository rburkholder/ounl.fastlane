#!/bin/bash
clang \
  -I /usr/src/linux-4.19.39 \
  -I /usr/src/linux-4.19.39/include/uapi \
  -I /usr/src/linux-4.19.39/arch/x86/indclude/uapi \
  -I /usr/include/x86_64-linux-gnu \
  -O2 -target bpf -c $1.c -o $1.o

  #-I /usr/src/linux-headers-4.19.0-5-common/include \
