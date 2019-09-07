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
#include <linux/bpf.h>
#include <libbpf.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <error.h>
#include <arpa/inet.h>
//#include <samples/bpf/bpf_load.h>
}

// example:
// https://developers.redhat.com/blog/2018/12/17/using-xdp-maps-rhel8/
// https://github.com/pabeni/xdp_walkthrough_examples/tree/master/sample_3_1

#include <AppFastLane/bpf/map_common.h>

XdpFlow::XdpFlow( asio::io_context& context )
: m_context( context )
 ,m_timer( context )
{
  std::cout << "XdpFlow start" << std::endl;

  struct bpf_object *objProgram;
  int prog_fd, map_fd;

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

  //m_if_index = 1; // use lo for now
  m_if_index = 4;
  __u32 xdp_flags( XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE );

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

  // TODO: load for all interfaces, will need to be supplied with if_indexes
  int status = bpf_set_link_xdp_fd(m_if_index, prog_fd, 0 );
  std::cout << "*** bpf_set_link_xdp_fd status: " << status << std::endl;

  m_nLoops = 10;
  Start();

}

XdpFlow::~XdpFlow() {
  std::cout << "XdpFlow stop" << std::endl;
  bpf_set_link_xdp_fd( m_if_index, -1, 0 );
}

void XdpFlow::Start() {

  namespace ph = std::placeholders;

  //m_bFinished = false;

  m_timer.expires_after( std::chrono::milliseconds( 990) );
  m_timer.async_wait( std::bind( &XdpFlow::UpdateStats, this, ph::_1 ) );
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

void XdpFlow::UpdateStats( const boost::system::error_code& ) {

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
