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

// mac stats
struct bpf_map_def SEC("maps") map_mac_stats = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof( mac_t ),
  .value_size = sizeof( struct stats_t ),
  .max_entries = 2048,
};

// packet counter for each 2 byte ethernet protocol number
struct bpf_map_def SEC("maps") map_protocol_stats = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof( __u16 ),
  .value_size = sizeof( __u64 ),
  .max_entries = 128,
};

// ipv4 stats
struct bpf_map_def SEC("maps") map_ipv4_stats = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof( ipv4_t ),
  .value_size = sizeof( struct stats_t ),
  .max_entries = 2048,
};

// ipv6 stats
struct bpf_map_def SEC("maps") map_ipv6_stats = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof( struct map_ipv6_key_t ),
  .value_size = sizeof( struct stats_t ),
  .max_entries = 2048,
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
//SEC("xdp_sock1")
//int xdp_egress( struct xdp_md* ctx ) {
//  bpf_printk("xdp_sock_egress\n");
//  return XDP_PASS;
//}

SEC("xdp_sock_ingress")
int xdp_ingress( struct xdp_md* ctx ) {

  bpf_printk("xdp_sock_ingress\n");

  __u64 ns = bpf_ktime_get_ns();

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

  __u64 nBytesL2 = pDataEnd - pDataBgn; // TODO: is pDataEnd one beyond?

  // counters for mac address

  mac_t map_mac_key;
  struct stats_t* stats_ptr;

  __builtin_memcpy( map_mac_key, phdrEthernet->h_source, ETH_ALEN );
  stats_ptr = bpf_map_lookup_elem( &map_mac_stats, &map_mac_key );
  if ( NULL == stats_ptr ) {
    struct stats_t stats = {
      .if_index = ix_if_ingress,
      .stats.rx.bytes = 0,
      .stats.rx.packets = 0,
      .stats.tx.bytes = nBytesL2,
      .stats.tx.packets = 1,
    };
    bpf_map_update_elem( &map_mac_stats, &map_mac_key, &stats, BPF_ANY );
  }
  else {
    stats_ptr->if_index = ix_if_ingress,
    stats_ptr->stats.tx.bytes += nBytesL2;
    stats_ptr->stats.tx.packets ++;
  }

  __builtin_memcpy( map_mac_key, phdrEthernet->h_dest, ETH_ALEN );
  stats_ptr = bpf_map_lookup_elem( &map_mac_stats, &map_mac_key );
  if ( NULL == stats_ptr ) {
    struct stats_t stats = {
      .if_index = 0,
      .stats.rx.bytes = nBytesL2,
      .stats.rx.packets = 1,
      .stats.tx.bytes = 0,
      .stats.tx.packets = 0,
    };
    bpf_map_update_elem( &map_mac_stats, &map_mac_key, &stats, BPF_ANY );
  }
  else {
    // TODO: check ix_if_ingress
    stats_ptr->stats.rx.bytes += nBytesL2;
    stats_ptr->stats.rx.packets ++;
  }

  // *** counters for ethernet protocol

  __u16 protocolEth = phdrEthernet->h_proto; // network byte order

  __u64* protocol_value_ptr = bpf_map_lookup_elem( &map_protocol_stats, &protocolEth );
  if ( NULL == protocol_value_ptr ) {
    __u64 one = 1;
    bpf_map_update_elem( &map_protocol_stats, &protocolEth, &one, BPF_ANY );
  }
  else {
    *protocol_value_ptr += 1;
  }

  // *** determine if any packet pre-processing required

  enum xdp_action action = XDP_PASS;
  //bpf_printk("xdp_flow switch:\n");

  switch ( protocolEth ) {
    case __constant_htons(ETH_P_IP): { // ipv4 protocol
        // TODO: refactor into tail call
        //bpf_printk("xdp_flow ip\n");
        __u64 nBytesL3 = pDataEnd - ( pDataBgn + offset ); // TODO: is pDataEnd one beyond?
        struct iphdr* phdrIpv4;
        phdrIpv4 = pDataBgn + offset; // offset after struct ethhdr
        offset += sizeof(*phdrIpv4);  // offset to after ipv4 header
        if ( pDataBgn + offset > pDataEnd ) {
          // TODO: need a drop counter here (use an index into an array for passing to user space)
          bpf_printk("xdp_flow bpf_printk drop #2\n");
//          action = XDP_DROP;
        }
        else {

          struct stats_t* stats_ptr;

          // ipv4 source accounting
          stats_ptr = bpf_map_lookup_elem( &map_ipv4_stats, &phdrIpv4->saddr );
          if ( NULL == stats_ptr ) {
            struct stats_t stats = {
              .if_index = ix_if_ingress,
              .stats.rx.bytes = 0,
              .stats.rx.packets = 0,
              .stats.tx.bytes = nBytesL3,
              .stats.tx.packets = 1,
            };
            bpf_map_update_elem( &map_ipv4_stats, &phdrIpv4->saddr, &stats, BPF_ANY );
          }
          else {
            stats_ptr->if_index = ix_if_ingress,
            stats_ptr->stats.tx.bytes += nBytesL3;
            stats_ptr->stats.tx.packets ++;
          }

          // ipv4 destination accounting
          stats_ptr = bpf_map_lookup_elem( &map_ipv4_stats, &phdrIpv4->daddr );
          if ( NULL == stats_ptr ) {
            struct stats_t stats = {
              .if_index = 0,
              .stats.rx.bytes = nBytesL3,
              .stats.rx.packets = 1,
              .stats.tx.bytes = 0,
              .stats.tx.packets = 0,
            };
            bpf_map_update_elem( &map_ipv4_stats, &phdrIpv4->daddr, &stats, BPF_ANY );
          }
          else {
            // TODO: check ix_if_ingress
            stats_ptr->stats.rx.bytes += nBytesL3;
            stats_ptr->stats.rx.packets ++;
          }

        }
      }
      break;
    case __constant_htons(ETH_P_IPV6):
      // TODO: refactor into tail call
      break;
    case __constant_htons(ETH_P_ARP):
      // TODO: map with arp based info
      //bpf_printk("xdp_flow arp\n");
      break;
    case __constant_htons(ETH_P_8021Q): /* 802.1Q VLAN Extended Header  */
      // TODO: will need tail call to ipv4/ipv6 for statistics
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

  action = XDP_PASS;  // force a pass for now

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