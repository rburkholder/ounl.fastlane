/*
 * File:      map_mac.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sep. 6, 2019
 */
 
 struct map_mac_key_def {
  __u32 if_index;
  unsigned char mac_dst[ 6 ];
  unsigned char mac_src[ 6 ];
};

struct map_mac_value_def {
  __u64 packets;
  __u64 bytes;
  __u64 flags;
  // 1 updated by kernel, reset to 0 by user space
};

 