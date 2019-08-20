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
  ,m_io_work( asio::make_work_guard( m_context ) )
  ,m_nRows {}
  //,m_resolver( m_io )
{

  try {
    static const std::string sFileName( "app_fastlane.cfg" );

    static const std::string sNameSyslogServer( "syslog_server" );

    po::options_description config( "server" );
    config.add_options()
      ( sNameSyslogServer.c_str(),        po::value<std::string>(), "syslog server ip dns" )
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

  m_thread = std::move( std::thread( [this ]{ m_context.run(); }) );

  m_pModel = std::make_shared<Model1>();
  //m_pModel = std::make_shared<Wt::WStandardItemModel>(0, 4);
  m_pModel->setHeaderData( 0, Wt::WString("Time") );
  m_pModel->setHeaderData( 1, Wt::WString("TCP") );
  m_pModel->setHeaderData( 2, Wt::WString("UDP") );
  m_pModel->setHeaderData( 3, Wt::WString("ICMP") );

  m_pBpfSockStats = std::make_unique<Load>(
    m_context,
    [this](long long tcp, long long udp, long long icmp ){

      m_pModel->insertRow( m_nRows );
      Wt::WDateTime dt = Wt::WDateTime::currentDateTime();
      m_pModel->setData( m_pModel->index( m_nRows, 0 ), std::any( dt ) );
      m_pModel->setData( m_pModel->index( m_nRows, 1 ), std::any( tcp ) );
      m_pModel->setData( m_pModel->index( m_nRows, 2 ), std::any( udp ) );
      m_pModel->setData( m_pModel->index( m_nRows, 3 ), std::any( icmp ) );


    /*
      using pItem_t = std::unique_ptr<Wt::WStandardItem>;
      std::vector<pItem_t> vItem;

      pItem_t pCol0 = std::make_unique<Wt::WStandardItem>( 1, 1 );
      pCol0->setData( Wt::WDateTime::currentDateTime() );
      vItem.push_back( std::move( pCol0 ) );

      pItem_t pCol1 = std::make_unique<Wt::WStandardItem>( 1, 1 );
      pCol1->setData( tcp );
      vItem.push_back( std::move( pCol1 ) );

      pItem_t pCol2 = std::make_unique<Wt::WStandardItem>( 1, 1 );
      pCol2->setData( udp );
      vItem.push_back( std::move( pCol2 ) );

      pItem_t pCol3 = std::make_unique<Wt::WStandardItem>( 1, 1 );
      pCol3->setData( icmp );
      vItem.push_back( std::move( pCol3 ) );

      pItem_t pRow = std::make_unique<Wt::WStandardItem>( 1, 4 );
      pRow->appendColumn( std::move( vItem ) );
      */

      //m_pModel->appendRow( std::move( pRow ) );

      //m_pModel->setData( m_nRows, 0, Wt::WDateTime::currentDateTime() );
      //m_pModel->setData( m_nRows, 1, tcp );
      //m_pModel->setData( m_nRows, 2, udp );
      //m_pModel->setData( m_nRows, 3, icmp );
      m_nRows++;
    }
    );

}

Server::~Server() {
  m_pBpfSockStats.reset();
  m_io_work.reset();
  m_thread.join();
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

