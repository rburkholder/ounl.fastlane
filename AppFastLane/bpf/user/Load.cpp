/*
 * Load.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Aug. 16, 2019
 */

extern "C" {
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <samples/bpf/sock_example.h>
#include <samples/bpf/bpf_load.h>
}

//#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <stdexcept>
#include <string>
#include <chrono>
#include <functional>

#include "Load.h"

Load::Load( asio::io_context& context )
: m_context( context )
 ,m_bContinue( false ), m_bFinished( false )
 ,m_timer( m_context )
{

  static const std::string sFile( "bpf/sock_stats.o" );
  if ( 0 != load_bpf_file( (char*)sFile.c_str() ) ) {
    std::string sError( "Load::Load" );
    sError += bpf_log_buf;
    throw std::runtime_error( sError );
  }

 //read_trace_pipe();   , std::chrono::steady_clock::now() + std::chrono::milliseconds( 990)

  int sock = open_raw_sock("lo");

  if ( 0 != setsockopt( sock, SOL_SOCKET, SO_ATTACH_BPF, prog_fd, sizeof( prog_fd[0] ) ) ) {
    throw std::runtime_error( "Load::Load setsockopt" );
  }

  m_bContinue = true;
  Start();
}

Load::~Load() {
  m_bContinue = false;
  m_timer.cancel();
  while( !m_bFinished );  // TODO: need to set wait_event or atomic to wait on for completion
}

void Load::Start() {
  namespace ph = std::placeholders;

  m_bFinished = false;

  m_timer.expires_after( std::chrono::milliseconds( 990) );
  m_timer.async_wait( std::bind( &Load::UpdateStats, this, ph::_1 ) );
}

void Load::UpdateStats( const boost::system::error_code& ) {

  long long tcp_cnt, udp_cnt, icmp_cnt;
  int key;

  key = IPPROTO_TCP;
  assert( 0 == bpf_map_lookup_elem( map_fd[0], &key, &tcp_cnt) );

  key = IPPROTO_UDP;
  assert( 0 == bpf_map_lookup_elem( map_fd[0], &key, &udp_cnt ) );

  key = IPPROTO_ICMP;
  assert( 0 == bpf_map_lookup_elem( map_fd[0], &key, &icmp_cnt ) );

  m_bFinished = true;

  if ( m_bContinue ) {
    Start();
  }

  std::cout << "TCP: " << tcp_cnt << ", UDP: " << udp_cnt << ", ICMP: " << icmp_cnt <<std::endl;
}
