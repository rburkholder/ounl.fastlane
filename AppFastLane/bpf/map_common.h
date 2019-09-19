/*
 * File:      map_common.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sep. 6, 2019
 */

#pragma once

//#include <uapi/linux/if_ether.h>

// TODO: try mmap style data conveance of header information using trace queue

struct uni_stats {
  __u64 bytes;
  __u64 packets;
};

struct bidi_stats {
  struct uni_stats rx;
  struct uni_stats tx;
};

struct stats_t {
  __u32 if_index;
  __u32 dummy;  // 64 bit aligned?
  struct bidi_stats stats;
};

typedef unsigned char mac_t[ ETH_ALEN ];

struct map_mac_pair_key_t {
  unsigned char src[ ETH_ALEN ];
  unsigned char dst[ ETH_ALEN ];
};

typedef __u32 ipv4_t;

struct map_ipv4_pair_key_t {
  __u32 src;
  __u32 dst;
};

struct map_ipv6_key_t {
  unsigned char ipv6[16];
};

struct map_ipv6_pair_key_t {
  unsigned char src[16];
  unsigned char dst[16];
};

