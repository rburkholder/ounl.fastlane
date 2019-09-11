/*
 * File:      sock_stats.c
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Aug 2019
 */

#ifndef __attribute_const__
# define __attribute_const__
#endif

#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <bpf_helpers.h>

#include "../map_common.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") countmap = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 256,
};

SEC("socket")
int socket_prog(struct __sk_buff *skb) {
  int one = 1;
  int proto = load_byte(skb, ETH_HLEN + offsetof( struct iphdr, protocol ) );
  int* el = bpf_map_lookup_elem(&countmap, &proto);
  if ( el ) {
    (*el)++;
  }
  else {
    el = &one;	  
  }
  bpf_map_update_elem( &countmap, &proto, el, BPF_ANY );
  return 0;
}

char _license[] SEC("license") = "GPL";
