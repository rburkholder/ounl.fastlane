#!/bin/bash
clang \
  -I /usr/include/x86_64-linux-gnu \
  -I /usr/src/linux-4.19.39 \
  -I /usr/src/linux-headers-4.19.0-5-common/include \
  -O2 -target bpf  -c sock_stats.c -o sock_stats.o

