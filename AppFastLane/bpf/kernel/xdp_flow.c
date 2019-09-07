#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <tools/testing/selftests/bpf/bpf_helpers.h>

#include "../map_mac.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") map_mac = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct map_mac_key_def),
  .value_size = sizeof(struct map_mac_value_def),
  .max_entries = 1024,
};

struct bpf_map_def SEC("maps") map_protocol = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u16),
  .value_size = sizeof(__u64),
  .max_entries = 128,
};

SEC("xdp")
int xdp_flow( struct xdp_md *ctx ) {

  int ipsize = 0;
  void *pDataBgn = (void *)(long)ctx->data;
  void *pDataEnd = (void *)(long)ctx->data_end;
  struct ethhdr *eth = pDataBgn;
  struct iphdr *pIpHdr;

  ipsize = sizeof(*eth);
  pIpHdr = pDataBgn + ipsize; // offset after struct ethhdr
  ipsize += sizeof(struct iphdr); // calculate size of ethernet plus ip header
  if ( pDataBgn + ipsize > pDataEnd ) {
    return XDP_DROP;
  }

  struct map_mac_key_def map_mac_key;
  __builtin_memset( &map_mac_key, 0, sizeof( struct map_mac_key_def ) );

  map_mac_key.if_index = ctx->ingress_ifindex;
  __builtin_memcpy( &map_mac_key.mac_dst, eth->h_dest, 6 );
  __builtin_memcpy( &map_mac_key.mac_src, eth->h_source, 6 );

  __u64 nBytes = pDataEnd - pDataBgn;

  struct map_mac_value_def* map_mac_value_ptr = bpf_map_lookup_elem( &map_mac, &map_mac_key );
  if ( 0 == map_mac_value_ptr ) { // key was not found

    struct map_mac_value_def map_mac_value;
    //__builtin_memset( &map_mac_value, 0, sizeof( struct map_mac_value_def ) );

    map_mac_value.packets = 1;
    map_mac_value.bytes = nBytes;
    map_mac_value.flags = 1;

    bpf_map_update_elem( &map_mac, &map_mac_key, &map_mac_value, BPF_ANY );

  }
  else {
    map_mac_value_ptr->bytes += nBytes;
    map_mac_value_ptr->packets += 1;
    map_mac_value_ptr->flags = 1;
  }

  __u64 one = 1;
  //__u16 protocol = eth->h_proto;
  __u64* protocol_value_ptr = bpf_map_lookup_elem( &map_protocol, &eth->h_proto );
  if ( 0 == protocol_value_ptr ) {
    bpf_map_update_elem( &map_protocol, &eth->h_proto, &one, BPF_ANY );
  }
  else {
    *protocol_value_ptr += 1;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

// cp build/cmake.debug.linux.x86_64/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o x64/bpf/xdp_flow.o

// sudo ip link set dev tap-win10-v90 xdp obj build/cmake.debug.linux.x86_64/AppFastLane/bpf/kernel/CMakeFiles/xdp_flow.dir/xdp_flow.c.o sec xdp
// sudo ip link set dev tap-win10-v90 xdp off

//struct xdp_md {
//  __u32 data;
//  __u32 data_end;
//  __u32 data_meta;
//  /* Below access go through struct xdp_rxq_info */
//  __u32 ingress_ifindex; /* rxq->dev->ifindex */
//  __u32 rx_queue_index;  /* rxq->queue_index  */
//};
