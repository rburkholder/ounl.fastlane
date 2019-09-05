#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_flow( struct xdp_md *ctx ) {

  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;

  ipsize = sizeof(*eth);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);
  if (data + ipsize > data_end) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


//struct xdp_md {
//  __u32 data;
//  __u32 data_end;
//  __u32 data_meta;
//  /* Below access go through struct xdp_rxq_info */
//  __u32 ingress_ifindex; /* rxq->dev->ifindex */
//  __u32 rx_queue_index;  /* rxq->queue_index  */
//};
