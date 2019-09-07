/*
 * File:      xdp_flow.c
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sept 2019
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <tools/testing/selftests/bpf/bpf_helpers.h>

#include "../map_mac.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") map_mac = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_mac_key_def),
  .value_size = sizeof(struct map_mac_value_def),
  .max_entries = 1024,
};

struct bpf_map_def SEC("maps") map_protocol_stats = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u16),
  .value_size = sizeof(__u64),
  .max_entries = 128,
};

struct bpf_map_def SEC("maps") map_ipv4 = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_ipv4_key_def),
  .value_size = sizeof(struct map_stats_def),
  .max_entries = 1024,
};

struct bpf_map_def SEC("maps") map_ipv6 = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_ipv6_key_def),
  .value_size = sizeof(struct map_stats_def),
  .max_entries = 1024,
};

#define bpf_printk(fmt, ...)                                    \
({                                                              \
    char ____fmt[] = fmt;                            \
    bpf_trace_printk(____fmt, sizeof(____fmt),       \
        ##__VA_ARGS__);                 \
})

SEC("xdp")
int xdp_flow( struct xdp_md* ctx ) {

  void* pDataBgn = (void*)(long)ctx->data;
  void* pDataEnd = (void*)(long)ctx->data_end;

  struct ethhdr* phdrEthernet = pDataBgn;
  int offset = sizeof(*phdrEthernet);

  //bpf_printk("xdp_flow bpf_printk\n");

  if ( pDataBgn + offset > pDataEnd ) {
    bpf_printk("xdp_flow bpf_printk drop #1\n");
    return XDP_DROP;
  }

  struct map_mac_key_def map_mac_key;
  //__builtin_memset( &map_mac_key, 0, sizeof( struct map_mac_key_def ) );

  map_mac_key.if_index = ctx->ingress_ifindex;
  __builtin_memcpy( &map_mac_key.mac_dst, phdrEthernet->h_dest, 6 );
  __builtin_memcpy( &map_mac_key.mac_src, phdrEthernet->h_source, 6 );

  __u64 nBytes = pDataEnd - pDataBgn; // TODO: is pDataEnd one beyond?

  struct map_mac_value_def* map_mac_value_ptr = bpf_map_lookup_elem( &map_mac, &map_mac_key );
  if ( 0 == map_mac_value_ptr ) { // key was not found

    struct map_mac_value_def map_mac_value;
    //__builtin_memset( &map_mac_value, 0, sizeof( struct map_mac_value_def ) );

    map_mac_value.packets = 1;
    map_mac_value.bytes = nBytes;
    //map_mac_value.flags = 1;

    bpf_map_update_elem( &map_mac, &map_mac_key, &map_mac_value, BPF_ANY );

  }
  else {
    map_mac_value_ptr->bytes += nBytes;
    map_mac_value_ptr->packets += 1;
    //map_mac_value_ptr->flags = 1;
  }

  __u64 one = 1;
  __u64* protocol_value_ptr = bpf_map_lookup_elem( &map_protocol_stats, &phdrEthernet->h_proto );
  if ( 0 == protocol_value_ptr ) {
    bpf_map_update_elem( &map_protocol_stats, &phdrEthernet->h_proto, &one, BPF_ANY );
  }
  else {
    *protocol_value_ptr += 1;
  }

  __u16 protocol = phdrEthernet->h_proto;

  switch ( protocol ) {
    case __constant_htons(ETH_P_IP): {
        struct iphdr* phdrIpv4;
        phdrIpv4 = pDataBgn + offset; // offset after struct ethhdr
        offset += sizeof(*phdrIpv4);
        if ( pDataBgn + offset > pDataEnd ) {
          // TODO: need a drop counter here (use an index into an array for passing to user space)
          bpf_printk("xdp_flow bpf_printk drop #2\n");
          return XDP_DROP;
        }
        struct map_ipv4_key_def map_ipv4_key;
        map_ipv4_key.if_index = ctx->ingress_ifindex;
        map_ipv4_key.dst = phdrIpv4->daddr;
        map_ipv4_key.src = phdrIpv4->saddr;
        struct map_stats_def* map_stats_ptr = bpf_map_lookup_elem( &map_ipv4, &map_ipv4_key );
        if ( 0 == map_stats_ptr ) {
          struct map_stats_def map_stats = {
            .packets = 1,
            .bytes = pDataEnd - ( pDataBgn + offset ),
          };
          bpf_map_update_elem( &map_ipv4, &map_ipv4_key, &map_stats, BPF_ANY );
        }
        else {
          map_stats_ptr->packets ++;
          map_stats_ptr->bytes += pDataEnd - ( pDataBgn + offset );
        }
      }
      break;
    case __constant_htons(ETH_P_IPV6):
      break;
    case __constant_htons(ETH_P_ARP):
      break;
    case __constant_htons(ETH_P_8021Q): /* 802.1Q VLAN Extended Header  */
      break;
    case __constant_htons(ETH_P_8021AD): /* 802.1ad Service VLAN    */
      break;
    case __constant_htons(ETH_P_8021AH): /* 802.1ah Backbone Service Tag */
      break;
    case __constant_htons(ETH_P_PREAUTH): /* 802.11 Preauthentication */
      break;
  }


  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

// cp build/cmake.debug.linux.x86_64/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o x64/bpf/xdp_flow.o

// sudo ip link set dev tap-win10-v90 xdp obj build/cmake.debug.linux.x86_64/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o sec xdp
// sudo ip link set dev tap-win10-v90 xdp off

// cat /sys/kernel/debug/tracing/trace_pipe

//  echo 1 > /proc/sys/net/core/bpf_jit_enable

//struct xdp_md {
//  __u32 data;
//  __u32 data_end;
//  __u32 data_meta;
//  /* Below access go through struct xdp_rxq_info */
//  __u32 ingress_ifindex; /* rxq->dev->ifindex */
//  __u32 rx_queue_index;  /* rxq->queue_index  */
//};
