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
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <samples/bpf/bpf_load.h>
}

#include "../map_mac.h"

XdpFlow::XdpFlow( asio::io_context& context )
: m_context( context )
 ,m_timer( context )
{
  static const std::string sFile( "bpf/xdp_flow.o" );
  if ( 0 != load_bpf_file( (char*)sFile.c_str() ) ) {
    std::string sError( "XdpFlow::XdpFlow load_bpf_file" );
    sError += bpf_log_buf;
    throw std::runtime_error( sError );
  }

  //m_if_index = 1; // use lo for now
  m_if_index = 4;
  __u32 xdp_flags( XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE );

  int status = bpf_set_link_xdp_fd(m_if_index, prog_fd[ 0 ], 0 );
  std::cout << "*** bpf_set_link_xdp_fd status: " << status << std::endl;

  m_nLoops = 10;
  Start();

}

XdpFlow::~XdpFlow() {
  //bpf_set_link_xdp_fd( m_if_index, -1, 0 );
}

void XdpFlow::Start() {

  namespace ph = std::placeholders;

  //m_bFinished = false;

  m_timer.expires_after( std::chrono::milliseconds( 990) );
  m_timer.async_wait( std::bind( &XdpFlow::UpdateStats, this, ph::_1 ) );
}

void XdpFlow::UpdateStats( const boost::system::error_code& ) {

  struct map_mac_key_def mac_key_blank;
  struct map_mac_key_def mac_key_next;
  memset( &mac_key_blank, 0, sizeof( struct map_mac_key_def ) );

  struct map_mac_value_def mac_value;

  std::cout << "Emit map: mac addresses: " << std::endl;

  int status1 = bpf_map_get_next_key( map_fd[0], &mac_key_blank, &mac_key_next);
  while ( 0 == status1 ) {
    int status2 = bpf_map_lookup_elem( map_fd[0], &mac_key_next, &mac_value );
    if ( 0 == status2 ) {
      std::cout
        << "  "
        << mac_key_next.if_index
        << ","
        << HexDump<unsigned char*>( mac_key_next.mac_dst, mac_key_next.mac_dst + 6, ':' )
        << ","
        << HexDump<unsigned char*>( mac_key_next.mac_src, mac_key_next.mac_src + 6, ':' )
        << "," << mac_value.flags
        << "," << mac_value.bytes
        << "," << mac_value.packets
        << std::endl;
    }
    status1 = bpf_map_get_next_key( map_fd[0], &mac_key_next, &mac_key_next);
  }

  std::cout << "Emit map: protocol types: " << std::endl;

  boost::endian::big_uint16_t ethertype_blank;
  boost::endian::big_uint16_t ethertype_next;
  uint64_t count;

  status1 = bpf_map_get_next_key( map_fd[1], &ethertype_blank, &ethertype_next );
  while ( 0 == status1 ) {
    int status2 = bpf_map_lookup_elem( map_fd[1], &ethertype_next, &count );
    if ( 0 == status2 ) {
      std::cout << std::hex << "0x" << ethertype_next << "=" << std::dec << count << std::endl;
    }
    status1 = bpf_map_get_next_key( map_fd[1], &ethertype_next, &ethertype_next );
  }

  if ( 0 != m_nLoops ) {
    m_nLoops--;
    if ( 0 != m_nLoops ) {
      Start();
    }
    else {
      bpf_set_link_xdp_fd( m_if_index, -1, 0 );
    }

  }

}
