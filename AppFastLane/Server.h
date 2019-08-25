/* 
 * File:      Server.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   2019/08/16
 */

#ifndef SERVER_H
#define SERVER_H

// reason for existence:
//   expose the shared resources to each app via the server instance in the environment

#include <thread>

//#include <boost/asio/ip/tcp.hpp>
//#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include <Wt/WServer.h>
#include <Wt/WSignal.h>

#include "bpf/user/Load.h"
#include "netlink/interface.h"

//#include "CassandraClient.h"

//#include "creditcard/plugnpay.h"

// TODO: use pimpl at some point to hide structures and sub-systems

namespace asio = boost::asio;
//namespace ip = boost::asio::ip;

class Server: public Wt::WServer {
public:

  Server( int argc,
          char *argv[], 
          const std::string &wtConfigurationFile=std::string()
          );
  virtual ~Server();

  Wt::Signal<Wt::WDateTime, long long, long long, long long> m_signalStats;

//  using vByte_t = ounl::message::vByte_t;
//  using fCompose_t = CassandraClient::fCompose_t;
//  using fReply_t = std::function<void( vByte_t& )>;

//  void ComposeSendAwaitReply( fCompose_t&&, fReply_t&&);
//  void ComposeSendAwaitReply( const std::string& sSessionId, fCompose_t&&, fReply_t&&);
  
protected:
private:

  std::thread m_thread;
  asio::io_context m_context; // TODO:  convert to WServer::IOService
  asio::executor_work_guard<asio::io_context::executor_type> m_io_work;

  std::unique_ptr<Load> m_pBpfSockStats;

  interface m_interface;

  //ip::tcp::resolver m_resolver;
  
//  std::unique_ptr<CassandraClient> m_pcc;

//  void HandleReply( fReply_t&& fReply, vByte_t&& v );

};

#endif /* SERVER_H */

