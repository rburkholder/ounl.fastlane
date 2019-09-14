/*
 * File:      XdpFlow.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sep. 5, 2019
 */

#include <string>
#include <chrono>
#include <iostream>
#include <stdexcept>

#include <boost/endian/arithmetic.hpp>

#include <oneunified/HexDump.h>

#include "XdpFlow.h"

extern "C" {
#include <tools/include/linux/compiler.h>

#include <unistd.h>
#include <error.h>
#include <stdlib.h>

#include <sys/resource.h>

#include <uapi/linux/types.h>
//#include <uapi/linux/bpf.h>
//#include <libbpf.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <uapi/linux/if_link.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmpv6.h>

#include <samples/bpf/bpf_load.h>
}

// example:
// https://developers.redhat.com/blog/2018/12/17/using-xdp-maps-rhel8/
// https://github.com/pabeni/xdp_walkthrough_examples/tree/master/sample_3_1

#include <AppFastLane/bpf/map_common.h>

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

class XdpFlow_impl {
public:

  XdpFlow_impl();
  ~XdpFlow_impl();

  void UpdateStats();

protected:
private:

  struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
  };

  struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx;

    //struct stats_record stats;
    //struct stats_record prev_stats;
  };

  struct config {
    __u32 xdp_flags;
    int ifindex;
    char *ifname;
    char ifname_buf[IF_NAMESIZE];
    int redirect_ifindex;
    char *redirect_ifname;
    char redirect_ifname_buf[IF_NAMESIZE];
    bool do_unload;
    bool reuse_maps;
    char pin_dir[512];
    char filename[512];
    char progsec[32];
    char src_mac[18];
    char dest_mac[18];
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
  } m_config;

  int m_if_index;

  int m_mapMac_fd;
  int m_mapProtocol_fd;
  int m_mapIpv4_fd;
  int m_mapXsk_fd;

  struct xsk_umem_info* m_umem;
  struct xsk_socket_info* m_xsk_socket;

  inline __u32 xsk_ring_prod__free(struct xsk_ring_prod* r ) {
    r->cached_cons = *r->consumer + r->size;
    return r->cached_cons - r->cached_prod;
  }

  struct XdpFlow_impl::xsk_umem_info* configure_xsk_umem(void* buffer, uint64_t size) ;
  uint64_t xsk_alloc_umem_frame(struct xsk_socket_info* xsk);
  void xsk_free_umem_frame( struct xsk_socket_info* xsk, uint64_t frame );
  uint64_t xsk_umem_free_frames(struct xsk_socket_info* xsk);
  struct xsk_socket_info* xsk_configure_socket(struct config* cfg,
                                               struct xsk_umem_info* umem);

};

XdpFlow_impl::XdpFlow_impl() {
  struct bpf_object *objProgram;
  int prog_fd;

  void *packet_buffer;
  uint64_t packet_buffer_size;
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};

  //m_if_index = 1; // use lo for now
  m_if_index = 4;
  //__u32 xdp_flags( XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE );
  //__u32 xdp_flags( XDP_FLAGS_SKB_MODE  );

//  struct config cfg = {
  m_config.ifindex   = -1;
  m_config.xdp_flags = XDP_FLAGS_SKB_MODE;
  m_config.do_unload = false;
//    .filename = "",
//    .progsec = "xdp_sock"
//  };
  *m_config.filename = 0;
  strcpy( m_config.progsec, "xdp_sock" );

  struct bpf_map* mapMac = bpf_object__find_map_by_name(objProgram, "map_mac");
  if (!mapMac)
    error(1, errno, "can't load map_mac");
  m_mapMac_fd = bpf_map__fd(mapMac);
  if (m_mapMac_fd < 0)
    error(1, errno, "can't get map_mac fd");

  struct bpf_map* mapProtocol = bpf_object__find_map_by_name(objProgram, "map_protocol_stats");
  if (!mapProtocol)
    error(1, errno, "can't load map_protocol_stats");
  m_mapProtocol_fd = bpf_map__fd(mapProtocol);
  if (m_mapProtocol_fd < 0)
    error(1, errno, "can't get map_protocol_stats fd");

  struct bpf_map* mapIpv4 = bpf_object__find_map_by_name(objProgram, "map_ipv4");
  if (!mapIpv4)
    error(1, errno, "can't load map_ipv4_stats");
  m_mapIpv4_fd = bpf_map__fd(mapIpv4);
  if (m_mapIpv4_fd < 0)
    error(1, errno, "can't get map_ipv4_stats fd");

  struct bpf_map* mapXsk = bpf_object__find_map_by_name(objProgram, "map_xsk");
  if (!mapXsk)
    error(1, errno, "can't load map_xsk");
  m_mapXsk_fd = bpf_map__fd(mapXsk);
  if (m_mapXsk_fd < 0)
    error(1, errno, "can't get m_mapXsk fd");

  struct bpf_prog_load_attr prog_load_attr = {
    .file = "bpf/xdp_flow.o",
    .prog_type = BPF_PROG_TYPE_XDP,
  };

  if (bpf_prog_load_xattr(&prog_load_attr, &objProgram, &prog_fd))
    error(1, errno, "can't load %s", prog_load_attr.file);

//  static const std::string sFile( "bpf/xdp_flow.o" );
//  if ( 0 != load_bpf_file( (char*)sFile.c_str() ) ) {
//    std::string sError( "XdpFlow::XdpFlow load_bpf_file" );
//    sError += bpf_log_buf;
//    throw std::runtime_error( sError );
//  }

  // TODO: load for all interfaces, will need to be supplied with if_indexes
  int status = bpf_set_link_xdp_fd(m_if_index, prog_fd, m_config.xdp_flags );
  std::cout << "*** bpf_set_link_xdp_fd status: " << status << std::endl;

  /* Allow unlimited locking of memory, so all memory needed for packet
   * buffers can be locked.
   */
  if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
    std::string sError( "ERROR: setrlimit(RLIMIT_MEMLOCK) " );
    sError += strerror(errno);
    throw std::runtime_error( sError );
  }

  /* Allocate memory for NUM_FRAMES of the default XDP frame size */
  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
  if (posix_memalign(&packet_buffer,
                     getpagesize(), /* PAGE_SIZE aligned */
                     packet_buffer_size)) {
    std::string sError( "ERROR: Can't allocate buffer memory " );
    sError += strerror(errno);
    throw std::runtime_error( sError );
  }

  /* Initialize shared packet_buffer for umem usage */
  m_umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
  if ( m_umem == NULL) {
    fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Open and configure the AF_XDP (xsk) socket */
  m_config.ifindex = m_if_index;  // TODO: deal with this if there is a loop
  m_xsk_socket = xsk_configure_socket(&m_config, m_umem);
  if ( m_xsk_socket == NULL) {
    fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
};

XdpFlow_impl::~XdpFlow_impl() {
  /* Cleanup */
  xsk_socket__delete(m_xsk_socket->xsk);
  xsk_umem__delete(m_umem->umem);
  //xdp_link_detach( m_config.ifindex, m_config.xdp_flags, 0);
  bpf_set_link_xdp_fd( m_if_index, -1, 0 ); // TODO: deal with multiple interfaces
};

struct XdpFlow_impl::xsk_umem_info* XdpFlow_impl::configure_xsk_umem(void *buffer, uint64_t size) {

  struct xsk_umem_info *umem;
  int ret;

  umem = (struct xsk_umem_info*)calloc(1, sizeof(*umem));
  if (!umem)
    return NULL;

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
             NULL);
  if (ret) {
    errno = -ret;
    return NULL;
  }

  umem->buffer = buffer;
  return umem;
}

uint64_t XdpFlow_impl::xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

void XdpFlow_impl::xsk_free_umem_frame(struct xsk_socket_info* xsk, uint64_t frame) {
  assert(xsk->umem_frame_free < NUM_FRAMES);

  xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

uint64_t XdpFlow_impl::xsk_umem_free_frames( struct xsk_socket_info* xsk ) {
  return xsk->umem_frame_free;
}

struct XdpFlow_impl::xsk_socket_info* XdpFlow_impl::xsk_configure_socket(
  struct config* cfg,
  struct xsk_umem_info* umem)
{
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info *xsk_info;
  uint32_t idx;
  uint32_t prog_id = 0;
  int i;
  int ret;

  xsk_info = (struct xsk_socket_info *)calloc(1, sizeof(*xsk_info));
  if (!xsk_info)
    return NULL;

  xsk_info->umem = umem;
  xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  xsk_cfg.libbpf_flags = 0;
  xsk_cfg.xdp_flags = cfg->xdp_flags;
  xsk_cfg.bind_flags = cfg->xsk_bind_flags;
  ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
         cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
         &xsk_info->tx, &xsk_cfg);

  if (ret)
    goto error_exit;

  ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
  if (ret)
    goto error_exit;

  /* Initialize umem frame allocation */

  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

  xsk_info->umem_frame_free = NUM_FRAMES;

  /* Stuff the receive path with buffers, we assume we have enough */
  ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
             XSK_RING_PROD__DEFAULT_NUM_DESCS,
             &idx);

  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    goto error_exit;

  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
    *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
      xsk_alloc_umem_frame(xsk_info);

  xsk_ring_prod__submit(&xsk_info->umem->fq,
            XSK_RING_PROD__DEFAULT_NUM_DESCS);

  return xsk_info;

error_exit:
  errno = -ret;
  return NULL;
}

void emit( __u32 addr ) {
  unsigned char* p( (unsigned char*)&addr );
  std::cout
    << (uint16_t)p[0]
    << "." << (uint16_t)p[1]
    << "." << (uint16_t)p[2]
    << "." << (uint16_t)p[3]
    ;
}

void XdpFlow_impl::UpdateStats() {

  struct map_mac_key_def mac_key_blank;
  struct map_mac_key_def mac_key_next;
  memset( &mac_key_blank, 0, sizeof( struct map_mac_key_def ) );

  struct map_mac_value_def mac_value;

  std::cout << "Emit map: mac addresses: " << std::endl;

  int status1 = bpf_map_get_next_key( m_mapMac_fd, &mac_key_blank, &mac_key_next);
  while ( 0 == status1 ) {
    int status2 = bpf_map_lookup_elem( m_mapMac_fd, &mac_key_next, &mac_value );
    if ( 0 == status2 ) {
      std::cout
        << "  "
        << mac_key_next.if_index
        << ","
        << HexDump<unsigned char*>( mac_key_next.mac_dst, mac_key_next.mac_dst + 6, ':' )
        << ","
        << HexDump<unsigned char*>( mac_key_next.mac_src, mac_key_next.mac_src + 6, ':' )
        //        << "," << mac_value.flags
        << "," << mac_value.bytes
        << "," << mac_value.packets
        << std::endl;
//      mac_value.flags = 0;
      // status2 = bpf_map_update_elem( map_fd[0], &mac_key_next, &mac_value, BPF_EXIST );
    }
    status1 = bpf_map_get_next_key( m_mapMac_fd, &mac_key_next, &mac_key_next);
  }

  std::cout << "Emit map: protocol types: " << std::endl;

  boost::endian::big_uint16_t ethertype_blank {};
  boost::endian::big_uint16_t ethertype_next {};
  uint64_t count;

  status1 = bpf_map_get_next_key( m_mapProtocol_fd, &ethertype_blank, &ethertype_next );
  while ( 0 == status1 ) {
    int status2 = bpf_map_lookup_elem( m_mapProtocol_fd, &ethertype_next, &count );
    if ( 0 == status2 ) {
      std::cout << std::hex << "0x" << ethertype_next << "=" << std::dec << count << std::endl;
    }
    status1 = bpf_map_get_next_key( m_mapProtocol_fd, &ethertype_next, &ethertype_next );
  }

  struct map_ipv4_key_def map_ipv4_key_blank = {
    .if_index = 0,
    .dst = 0,
    .src = 0
  };

  struct map_ipv4_key_def map_ipv4_key_next = map_ipv4_key_blank;
  struct map_stats_def map_stats;

  status1 = bpf_map_get_next_key( m_mapIpv4_fd, &map_ipv4_key_blank, &map_ipv4_key_next );
  while ( 0 == status1 ) {
    int status2 = bpf_map_lookup_elem( m_mapIpv4_fd, &map_ipv4_key_next, &map_stats );
    if ( 0 == status2 ) {
      std::cout << map_ipv4_key_next.if_index << ",";
      emit( map_ipv4_key_next.dst );
      std::cout << ",";
      emit( map_ipv4_key_next.src );
      std::cout
        << "," << map_stats.packets
        << "," << map_stats.bytes
        << std::endl;
    }
    status1 = bpf_map_get_next_key( m_mapIpv4_fd, &map_ipv4_key_next, &map_ipv4_key_next );
  }

}

//
// ==== XdpFlow
//

XdpFlow::XdpFlow( asio::io_context& context )
: m_context( context )
 ,m_timer( context )
{
  std::cout << "XdpFlow start" << std::endl;

  m_pXdpFlow_impl = std::make_unique<XdpFlow_impl>();

  /* Receive and count packets than drop them */
  //rx_and_process(&cfg, xsk_socket);

  m_nLoops = 10;
  Start();

}

XdpFlow::~XdpFlow() {
  std::cout << "XdpFlow stop" << std::endl;
}

void XdpFlow::Start() {

  namespace ph = std::placeholders;

  //m_bFinished = false;

  m_timer.expires_after( std::chrono::milliseconds( 990) );
  m_timer.async_wait( std::bind( &XdpFlow::UpdateStats, this, ph::_1 ) );
}

void XdpFlow::UpdateStats( const boost::system::error_code& ) {

  m_pXdpFlow_impl->UpdateStats();

  if ( 0 != m_nLoops ) {
    m_nLoops--;
    if ( 0 != m_nLoops ) {
      Start();
    }
    else {
      //bpf_set_link_xdp_fd( m_if_index, -1, 0 );
    }

  }

}
