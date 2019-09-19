/*
 * File:      Server.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on October 14, 2018, 12:08 PM
 */

#include <fstream>
#include <vector>

#include <boost/log/trivial.hpp>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/asio/post.hpp>

//#include <OunlMessage/Append.h>
//#include <OunlMessage/Message.h>
//#include <OunlMessage/buffer_on_strand.h>

#include <Wt/WString.h>
#include <Wt/WDateTime.h>
#include <Wt/WStandardItem.h>

#include "log_syslog.h"

#include "Server.h"

Server::Server(
   int argc
  ,char *argv[]
  ,const std::string &wtConfigurationFile
)
: Wt::WServer( argc, argv, wtConfigurationFile )
 ,m_ePoll(EPoll::Quiescent)
 ,m_strand( m_context )
 ,m_io_work( asio::make_work_guard( m_context ) )
 ,m_timer( m_context )
 ,m_interface(
    m_context,
    [this](const interface::link_t&& link,const struct rtnl_link_stats64& stats){ // function to receive initial interface list and statistics
      //BOOST_LOG_TRIVIAL(trace) << "initial on index=" << link.if_index;
      asio::post(
        m_strand,
        [this,link_=std::move(link), stats](){
          mapLink_t::iterator iterMap = m_mapLink.find( link_.if_index );
          if ( m_mapLink.end() == iterMap ) {
            m_mapLink.emplace( link_.if_index, link_t( link_, stats ) );
          }
          else {
            //  but but but this shouldn't happen, it does, need to fix interface.cpp
            //iterMap->second.stats = stats_;
            //iterMap->second.signalStats64( stats_ ); // doing diffs instead
            rtnl_link_stats64& prev( iterMap->second.stats );
            if ( 0 != iterMap->second.signalStats64.num_slots() ) {
              rtnl_link_stats64 diff;
              // TODO: may emit signal per attribute instead?
              // TODO: turn this into macro
              diff.rx_packets          = stats.rx_packets          - prev.rx_packets;
              diff.tx_packets          = stats.tx_packets          - prev.tx_packets;
              diff.rx_bytes            = stats.rx_bytes            - prev.rx_bytes;
              diff.tx_bytes            = stats.tx_bytes            - prev.tx_bytes;
              diff.rx_errors           = stats.rx_errors           - prev.rx_errors;
              diff.tx_errors           = stats.tx_errors           - prev.tx_errors;
              diff.rx_dropped          = stats.rx_dropped          - prev.rx_dropped;
              diff.tx_dropped          = stats.tx_dropped          - prev.tx_dropped;
              diff.multicast           = stats.multicast           - prev.multicast;
              diff.collisions          = stats.collisions          - prev.collisions;
              diff.rx_length_errors    = stats.rx_length_errors    - prev.rx_length_errors;
              diff.rx_over_errors      = stats.rx_over_errors      - prev.rx_over_errors;
              diff.rx_crc_errors       = stats.rx_crc_errors       - prev.rx_crc_errors;
              diff.rx_frame_errors     = stats.rx_frame_errors     - prev.rx_frame_errors;
              diff.rx_fifo_errors      = stats.rx_fifo_errors      - prev.rx_fifo_errors;
              diff.rx_missed_errors    = stats.rx_missed_errors    - prev.rx_missed_errors;
              diff.tx_aborted_errors   = stats.tx_aborted_errors   - prev.tx_aborted_errors;
              diff.tx_carrier_errors   = stats.tx_carrier_errors   - prev.tx_carrier_errors;
              diff.tx_fifo_errors      = stats.tx_fifo_errors      - prev.tx_fifo_errors;
              diff.tx_heartbeat_errors = stats.tx_heartbeat_errors - prev.tx_heartbeat_errors;
              diff.tx_window_errors    = stats.tx_window_errors    - prev.tx_window_errors;
              diff.rx_compressed       = stats.rx_compressed       - prev.rx_compressed;
              diff.tx_compressed       = stats.tx_compressed       - prev.tx_compressed;
              diff.rx_nohandler        = stats.rx_nohandler        - prev.rx_nohandler;
              iterMap->second.signalStats64( diff );
            }
            prev = stats;
          }
        } );
    },
    [this](const int if_index,const struct rtnl_link_stats64& stats){ // function to receive periodic statistics
      BOOST_LOG_TRIVIAL(trace) << "periodic on index=" << if_index;
      asio::post(
        m_strand,
        [this,if_index,stats](){
          mapLink_t::iterator iterMap = m_mapLink.find( if_index );
          if ( m_mapLink.end() != iterMap ) {
            rtnl_link_stats64& prev( iterMap->second.stats );
            if ( 0 != iterMap->second.signalStats64.num_slots() ) {
              rtnl_link_stats64 diff;
              // TODO: may emit signal per attribute instead?
              // TODO: turn this into macro
              diff.rx_packets          = stats.rx_packets          - prev.rx_packets;
              diff.tx_packets          = stats.tx_packets          - prev.tx_packets;
              diff.rx_bytes            = stats.rx_bytes            - prev.rx_bytes;
              diff.tx_bytes            = stats.tx_bytes            - prev.tx_bytes;
              diff.rx_errors           = stats.rx_errors           - prev.rx_errors;
              diff.tx_errors           = stats.tx_errors           - prev.tx_errors;
              diff.rx_dropped          = stats.rx_dropped          - prev.rx_dropped;
              diff.tx_dropped          = stats.tx_dropped          - prev.tx_dropped;
              diff.multicast           = stats.multicast           - prev.multicast;
              diff.collisions          = stats.collisions          - prev.collisions;
              diff.rx_length_errors    = stats.rx_length_errors    - prev.rx_length_errors;
              diff.rx_over_errors      = stats.rx_over_errors      - prev.rx_over_errors;
              diff.rx_crc_errors       = stats.rx_crc_errors       - prev.rx_crc_errors;
              diff.rx_frame_errors     = stats.rx_frame_errors     - prev.rx_frame_errors;
              diff.rx_fifo_errors      = stats.rx_fifo_errors      - prev.rx_fifo_errors;
              diff.rx_missed_errors    = stats.rx_missed_errors    - prev.rx_missed_errors;
              diff.tx_aborted_errors   = stats.tx_aborted_errors   - prev.tx_aborted_errors;
              diff.tx_carrier_errors   = stats.tx_carrier_errors   - prev.tx_carrier_errors;
              diff.tx_fifo_errors      = stats.tx_fifo_errors      - prev.tx_fifo_errors;
              diff.tx_heartbeat_errors = stats.tx_heartbeat_errors - prev.tx_heartbeat_errors;
              diff.tx_window_errors    = stats.tx_window_errors    - prev.tx_window_errors;
              diff.rx_compressed       = stats.rx_compressed       - prev.rx_compressed;
              diff.tx_compressed       = stats.tx_compressed       - prev.tx_compressed;
              diff.rx_nohandler        = stats.rx_nohandler        - prev.rx_nohandler;
              iterMap->second.signalStats64( diff );
            }
            prev = stats;
          }
          else {
            // some sort of error?
          }
        });
    }
   )
{

  try {
    static const std::string sFileName( "app_fastlane.cfg" );

    static const std::string sNameSyslogServer( "syslog_server" );

    po::options_description config( "server" );
    config.add_options()
      ( sNameSyslogServer.c_str(), po::value<std::string>(), "syslog server ip dns" )
      ;
    po::variables_map vm;

    std::ifstream ifs( sFileName.c_str() );
    if ( !ifs ) {
      BOOST_LOG_TRIVIAL(error) << "file " << sFileName << " does not exist";
    }
    else {
      po::store( po::parse_config_file( ifs, config), vm );
    }

    if ( 0 < vm.count( sNameSyslogServer ) ) {
      BOOST_LOG_TRIVIAL(info) << "syslog server: " << vm[sNameSyslogServer].as<std::string>();
    }

    // TODO: need to validate all required parameters are supplied

  }
  catch ( std::exception& e ) {
    BOOST_LOG_TRIVIAL(error) << "server.cpp config parse error: " << e.what();
    throw e; // need to terminate without config
  }

  //m_pcc = std::make_unique<CassandraClient>( m_io, m_resolver.resolve( m_sBlgcSrvrIp, "8794" ) );

  //this->log( "info" ) << "constructor connects to: " << m_sBlgcSrvrIp << ":8794";
  this->log( "info" ) << "server started with: '" << wtConfigurationFile << "'";

  ounl::log::init_native_syslog();

  //m_thread = std::move( std::thread( [this ]{ m_context.run(); }) );
  m_vThread.emplace_back( std::move( std::thread( [this]{m_context.run(); } ) ) );
  m_vThread.emplace_back( std::move( std::thread( [this]{m_context.run(); } ) ) );
  m_vThread.emplace_back( std::move( std::thread( [this]{m_context.run(); } ) ) );

  /*
  m_pBpfSockStats = std::make_unique<SockStats>(
    m_context,
    [this](long long tcp, long long udp, long long icmp ){

      Wt::WDateTime dt = Wt::WDateTime::currentDateTime();
      m_signalStats.emit( dt, tcp, udp, icmp );

    }
    );
    */

  m_pBpfXdpFlow = std::make_unique<XdpFlow>( m_context );

  m_ePoll = EPoll::Running;
  asio::post( m_strand, std::bind(&Server::Poll, this ) );
}

Server::~Server() {

  m_ePoll = EPoll::Stop;
  m_timer.cancel();
  while (EPoll::Stopped != m_ePoll );  // will this run forever?

  //m_pBpfSockStats.reset();
  m_pBpfXdpFlow.reset();
  m_io_work.reset();
  //m_thread.join();
  for ( std::thread& thread: m_vThread ) {
    if ( thread.joinable() ) thread.join();
  }
}

void Server::Poll() {
  switch ( m_ePoll ) {
    case EPoll::Quiescent:
      // is this reachable/relevant?  what should the operation be?
      break;
    case EPoll::Running: {
        m_timer.expires_after( std::chrono::milliseconds( 200 ) );
        m_timer.async_wait(
          [this](const boost::system::error_code& error){
            int status;
            if ( error || (EPoll::Stop == m_ePoll ) ) {
              m_ePoll = EPoll::Stopped; // does this lead to a race condition at all?
            }
            else {


              asio::post( m_strand, std::bind(&Server::Poll, this ) );
            }

          });
        }
      break;
    case EPoll::Stop: {
        m_ePoll = EPoll::Stopped;
      }
      break;
    case EPoll::Stopped:
      break;
  }
}

void Server::GetInterfaceList( fInterfaceItem_t&& fInterfaceItem ) {
  asio::post(
    m_strand,
    [this,fInterfaceItem_=std::move(fInterfaceItem)](){ // thread resistant access to interface map
      for ( const mapLink_t::value_type& vt: m_mapLink ) {
        std::cout << "interface: " << vt.second.link.if_name << std::endl;
        fInterfaceItem_( vt.first, vt.second.link.if_name );
      }
    }
    );
}

void Server::InterfaceStats64( int if_index, slotStats64_t slot, fInterfaceStats64Connection&& f ) {
  asio::post(
    m_strand,
    [this,if_index,slot_=std::move(slot),f_=std::move(f)](){
      mapLink_t::iterator iterLink = m_mapLink.find( if_index );
      if ( m_mapLink.end() != iterLink ) {
        boost::signals2::connection connection = iterLink->second.signalStats64.connect( slot_ );
        f_( connection );
      }
    }
    );
}

/*
void Server::ComposeSendAwaitReply( fCompose_t&& fCompose, fReply_t&& fReply) {
  m_pcc->ComposeSendAwaitReply(
    std::move( fCompose ),
    [this,fReply_=std::move(fReply)](vByte_t&& v){
      fReply_( v );
      m_pcc->ReleaseRx( std::move( v ) );
    });
}

void Server::ComposeSendAwaitReply( const std::string& sSessionId, fCompose_t&& fCompose, fReply_t&& fReply) {
  m_pcc->ComposeSendAwaitReply(
    std::move( fCompose ),
    [this,sSessionId,fReply_=std::move(fReply)](vByte_t&& v){
      assert( ounl::message::Queue::nReservation <= v.capacity() );
      post(
        sSessionId,
        [this,fReply__=std::move(fReply_),v_=std::move( v )]() mutable {
          //assert( ounl::message::Queue::nReservation <= v_.capacity() );
          fReply__( v_ );
          //assert( ounl::message::Queue::nReservation <= v_.capacity() );
          if ( ounl::message::Queue::nReservation <= v_.capacity() ) {
            m_pcc->ReleaseRx( std::move( v_ ) ); // perform release only if the lambda moved rather than copied
          }
        } );
      if ( 0 != v.capacity() ) { // for some reason the lambda above is a copy rather than a move
        m_pcc->ReleaseRx( std::move( v ) );
      }
    });
}

// TODO: see if this fixes the 'copy' problem above.
void Server::HandleReply( fReply_t&& fReply, vByte_t&& v ) {
  assert( ounl::message::Queue::nReservation <= v.capacity() );
  fReply( v );
  m_pcc->ReleaseRx( std::move( v ) );
}
*/
    // TODO: block until ConnectResult is returned?
    // TODO: close app if connection broken, or pause app and retry
    // TODO: will need multiple connections, as a backup

