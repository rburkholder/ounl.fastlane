/*
 * File:      map_common.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sep. 6, 2019
 */

#pragma once

extern "C" {
#include <uapi/linux/if_ether.h>
}
 
 struct map_ipv4_key_def {
  __u32 if_index;
  __u32 dst;
  __u32 src;
};

struct map_ipv6_key_def {
  __u32 if_index;
  unsigned char dst[16];
  unsigned char src[16];
};

 struct map_stats_def {
  __u64 packets;
  __u64 bytes;
};

 struct map_mac_key_def {
  __u32 if_index;
  unsigned char mac_dst[ ETH_ALEN ];
  unsigned char mac_src[ ETH_ALEN ];
};

struct map_mac_value_def {
  __u64 packets;
  __u64 bytes;
//  __u64 flags;  // won't sync properly, needs to be in value structure by itself
  // 1 updated by kernel, reset to 0 by user space
  // maybe migrate to the lock construct which may do this properly
};
