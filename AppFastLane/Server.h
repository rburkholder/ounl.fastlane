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

#include <map>
#include <thread>
#include <functional>

//#include <boost/asio/ip/tcp.hpp>
//#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/steady_timer.hpp>

#include <boost/signals2.hpp>

#include <Wt/WServer.h>
#include <Wt/WSignal.h>

//#include "bpf/user/SockStats.h"
#include "bpf/user/XdpFlow.h"
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

  //using signalStats64_t = boost::signals2::signal<void(Wt::WDateTime, const rtnl_link_stats64&)>;
  using signalStats64_t = boost::signals2::signal<void(const rtnl_link_stats64&)>;
  using slotStats64_t = signalStats64_t::slot_type;
  signalStats64_t m_signalStats64;

  using fInterfaceItem_t = std::function<void(int,const std::string&)>; // if_index, if_name
  void GetInterfaceList( fInterfaceItem_t&& );

  using fInterfaceStats64Connection = std::function<void(boost::signals2::connection)>;
  void InterfaceStats64( int if_index, slotStats64_t, fInterfaceStats64Connection&& );

//  using vByte_t = ounl::message::vByte_t;
//  using fCompose_t = CassandraClient::fCompose_t;
//  using fReply_t = std::function<void( vByte_t& )>;

//  void ComposeSendAwaitReply( fCompose_t&&, fReply_t&&);
//  void ComposeSendAwaitReply( const std::string& sSessionId, fCompose_t&&, fReply_t&&);

protected:
private:

  enum class EPoll { Quiescent, Running, Stop, Stopped } m_ePoll;

  using vThread_t = std::vector<std::thread>;

  vThread_t m_vThread;
  asio::io_context m_context; // TODO:  convert to WServer::IOService
  asio::io_context::strand m_strand; // sync various operations on interface lists and statistics
  asio::executor_work_guard<asio::io_context::executor_type> m_io_work;

  asio::steady_timer m_timer;

  //std::unique_ptr<SockStats> m_pBpfSockStats;
  std::unique_ptr<XdpFlow> m_pBpfXdpFlow;

  interface m_interface;

  struct link_t {
    interface::link_t link;
    rtnl_link_stats64 stats;
    signalStats64_t signalStats64;
    link_t( const interface::link_t& link_ )
    : link( link_ )
    {}
  };

  using mapLink_t = std::map<int,link_t>;
  mapLink_t m_mapLink;

//  std::unique_ptr<CassandraClient> m_pcc;

  void Poll();

};

#endif /* SERVER_H */

