/*
 * File:      xdp_flow.c
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sept 2019
 */

//#include <linux/compiler.h>
//#include <tools/include/linux/compiler.h>
//#include <linux/compiler.h>

// kernel module to pick and choose packets to redirect

// inspiration:
//  https://github.com/xdp-project/xdp-tutorial/blob/master/advanced03-AF_XDP/af_xdp_kern.c

// Documentation:
//   Documentation/networking/af_xdp.rst

#ifndef __attribute_const__
# define __attribute_const__
#endif

#include <uapi/linux/types.h>
#include <uapi/linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

#include <bpf_helpers.h>
#include "../map_common.h"

#define SEC(NAME) __attribute__((section(NAME), used))

// pass ifindex, dst mac, src mac to userland
struct bpf_map_def SEC("maps") map_mac = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_mac_key_def),
  .value_size = sizeof(struct map_mac_value_def),
  .max_entries = 1024,
};

// packet counter for each 2 byte ethernet protocol number
struct bpf_map_def SEC("maps") map_protocol_stats = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u16),
  .value_size = sizeof(__u64),
  .max_entries = 128,
};

// pass ifindex, dst ipv4, src ipv4 stats to userland
struct bpf_map_def SEC("maps") map_ipv4 = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_ipv4_key_def),
  .value_size = sizeof(struct map_stats_def),
  .max_entries = 1024,
};

// pass ifindex, dst ipv6, src ipv6 stats to userland
struct bpf_map_def SEC("maps") map_ipv6 = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_ipv6_key_def),
  .value_size = sizeof(struct map_stats_def),
  .max_entries = 1024,
};

//AF_XDP socket (XSK)
struct bpf_map_def SEC("maps") map_xsk = {
  .type = BPF_MAP_TYPE_XSKMAP,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

#define bpf_printk(fmt, ...)                                    \
({                                                              \
    char ____fmt[] = fmt;                            \
    bpf_trace_printk(____fmt, sizeof(____fmt),       \
        ##__VA_ARGS__);                 \
})

// need to maintain this order of programs
SEC( "xdp_sock_egress" )
int xdp_egress( struct xdp_md* ctx ) {
  bpf_printk("xdp_sock_egress\n");
  return XDP_PASS;
}

SEC("xdp_sock_ingress")
int xdp_ingress( struct xdp_md* ctx ) {
  
  bpf_printk("xdp_sock_ingress\n");

  void* pDataBgn = (void*)(long)ctx->data;
  void* pDataEnd = (void*)(long)ctx->data_end;
  __u32 ix_rx_queue   = ctx->rx_queue_index;
  __u32 ix_if_ingress = ctx->ingress_ifindex;

  struct ethhdr* phdrEthernet = pDataBgn;
  int offset = sizeof(*phdrEthernet);

  //bpf_printk("xdp_flow bpf_printk\n");

  if ( pDataBgn + offset > pDataEnd ) {
    bpf_printk("xdp_flow bpf_printk drop #1\n");
    return XDP_DROP;
  }

  // *** counters for mac address pairs

  struct map_mac_key_def map_mac_key;

  map_mac_key.if_index = ctx->ingress_ifindex;
  __builtin_memcpy( &map_mac_key.mac_dst, phdrEthernet->h_dest, 6 );
  __builtin_memcpy( &map_mac_key.mac_src, phdrEthernet->h_source, 6 );

  __u64 nBytes = pDataEnd - pDataBgn; // TODO: is pDataEnd one beyond?

  struct map_mac_value_def* map_mac_value_ptr = bpf_map_lookup_elem( &map_mac, &map_mac_key );
  if ( NULL == map_mac_value_ptr ) { // key was not found

    struct map_mac_value_def map_mac_value = {
      .packets = 1,
      .bytes = nBytes,
    };

    bpf_map_update_elem( &map_mac, &map_mac_key, &map_mac_value, BPF_ANY );
  }
  else {
    map_mac_value_ptr->bytes += nBytes;
    map_mac_value_ptr->packets ++;
  }

  // *** counters for ethernet protocol

  __u16 protocolEth = phdrEthernet->h_proto; // network byte order

  __u64 one = 1;
  __u64* protocol_value_ptr = bpf_map_lookup_elem( &map_protocol_stats, &protocolEth );
  if ( NULL == protocol_value_ptr ) {
    bpf_map_update_elem( &map_protocol_stats, &protocolEth, &one, BPF_ANY );
  }
  else {
    *protocol_value_ptr += 1;
  }
  
  // *** determine if any packet pre-processing required
  
  enum xdp_action action = XDP_PASS;
  bpf_printk("xdp_flow switch:\n");

  switch ( protocolEth ) {
    case __constant_htons(ETH_P_IP): { // ipv4 protocol
        bpf_printk("xdp_flow ip\n");
        struct iphdr* phdrIpv4;
        phdrIpv4 = pDataBgn + offset; // offset after struct ethhdr
        offset += sizeof(*phdrIpv4);  // offset to after ipv4 header
        if ( pDataBgn + offset > pDataEnd ) {
          // TODO: need a drop counter here (use an index into an array for passing to user space)
          bpf_printk("xdp_flow bpf_printk drop #2\n");
          action = XDP_DROP;
        }
        else {
          struct map_ipv4_key_def map_ipv4_key = {
            .if_index = ix_if_ingress,
            .dst = phdrIpv4->daddr,
            .src = phdrIpv4->saddr,
          };
          struct map_stats_def* map_stats_ptr = bpf_map_lookup_elem( &map_ipv4, &map_ipv4_key );
          if ( NULL == map_stats_ptr ) {
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
          action = XDP_REDIRECT;
        }
      }
      break;
    case __constant_htons(ETH_P_IPV6):
      break;
    case __constant_htons(ETH_P_ARP):
      bpf_printk("xdp_flow arp\n");
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

  // need to refine this and filter on specific ip address/port number from external map filter
  
  /* A set entry here means that the correspnding queue_id
   * has an active AF_XDP socket bound to it. */
//  if ( bpf_map_lookup_elem( &map_xsk, &ix_rx_queue ) )
// note the return, need to check return values
  switch ( action ) {
    case XDP_REDIRECT:
      return bpf_redirect_map( &map_xsk, ix_rx_queue, 0 );
      break;
    default:
      return action;
      break;
  }
  
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

// eclipse:
// cp build/cmake.debug.linux.x86_64/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o x64/bpf/xdp_flow.o

// clion:
// cp cmake-build-debug/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o x64/bpf/xdp_flow.o

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

// XDP_REDIRECT:
// rx_queue_index (slide 15):
// https://people.netfilter.org/hawk/presentations/LLC2018/XDP_LLC2018_redirect.pdf

// tuning network subsystem:
//  https://blog.packagecloud.io/eng/2016/06/22/monitoring-tuning-linux-networking-stack-receiving-data/

// ethtool eth0
// ethtool -i eth0
// ethtool -S eth0

// ip link set dev eth0 xdpgeneric off
// ip link set dev eth0 xdp off