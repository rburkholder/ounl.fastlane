/*
 * File:      interface.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 24, 2019
 */

#ifndef APPFASTLANE_NETLINK_INTERFACE_H_
#define APPFASTLANE_NETLINK_INTERFACE_H_

#include <map>
#include <functional>

#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/steady_timer.hpp>
//#include <boost/asio/io_context.hpp>

extern "C" {
#include <netlink/socket.h>
#include <netlink/cache.h>
}

namespace asio = boost::asio;

class interface {
public:
  struct link_t {
    int if_index;
    std::string if_name;
    std::string qdisk;
    uint8_t mac[6];
    uint8_t broadcast[6];
    bool bLowerUp;
    bool bUp;
    bool bRunning;
    bool bLoopback;
    bool bEthernet;
    link_t()
    : if_index {}
     ,bLowerUp( false ), bUp( false ), bRunning( false )
     ,bLoopback( false ), bEthernet( false )
    {
       for ( int ix = 0; ix < 6; ix++ ) {
         mac[ ix ] = broadcast[ ix ] = 0;
       }
    }
     // TODO: need to test that all members have been assigned
  }; // link_t

  using fLinkNew_t = std::function<void(const link_t&)>;
  using fLinkDel_t = std::function<void(int /*if_index*/)>;
  using fLinkStats_t = std::function<void(const int /*ifindex*/, const struct rtnl_link_stats64&)>;

  interface( asio::io_context&, fLinkNew_t&&, fLinkDel_t&&, fLinkStats_t&& );
  ~interface();

protected:
private:

  enum class EPoll { Quiescent, Running, Stop, Stopped } m_ePoll;

  fLinkNew_t m_fLinkNew;
  fLinkDel_t m_fLinkDel;
  fLinkStats_t m_fLinkStats;

  struct nl_sock* m_nl_sock_cmd;
  struct nl_sock* m_nl_sock_statistics;
  struct nl_sock* m_nl_sock_event;
  struct nl_sock* m_nl_sock_cache_link;

  //void decodeLinkDiag( struct nl_msg* );

  using mapLink_t = std::map<int,link_t>;
  mapLink_t m_mapLink;

  static int cbCmd_Msg_Link(struct nl_msg* msg, void* arg);
  static int cbCmd_Msg_Finished(struct nl_msg* msg, void* arg);

  static int cbCmd_Msg_LinkDelta(struct nl_msg* msg, void* arg);
  static int cbCmd_Msg_LinkInitialDump(struct nl_msg* msg, void* arg);
  static int cbCmd_Msg_LinkRegularDump(struct nl_msg* msg, void* arg);

  struct nl_cache*      m_cache_link;
  struct nl_cache_mngr* m_cache_link_mngr;

  static void cbCacheLinkInitial( struct nl_object*, void* );
  static void cbCacheLinkEvent1( struct nl_cache*, struct nl_object* obj, int, void* );
  static void cbCacheLinkEvent2(
      struct nl_cache*,
      struct nl_object* old_obj, struct nl_object* new_obj,
      uint64_t, int, void* );

  void Poll();
  //bool m_bPoll;
  asio::io_context& m_context;
  asio::io_context::strand m_strand;
  asio::steady_timer m_timer;
  size_t m_cntLoops;  // number of loops prior to dump request
};

#endif /* APPFASTLANE_NETLINK_INTERFACE_H_ */
