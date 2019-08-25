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

#include <thread>
//#include <functional>

extern "C" {
#include <netlink/socket.h>
#include <netlink/cache.h>
}

class interface {
public:
  interface();
  ~interface();
protected:
private:

  struct nl_sock* m_nl_sock_cmd;
  struct nl_sock* m_nl_sock_event;
  struct nl_sock* m_nl_sock_cache_link;

  static int cbCmd_Msg_Valid(struct nl_msg *msg, void *arg);
  static int cbCmd_Msg_Finished(struct nl_msg *msg, void *arg);
  static int cbLinkEvent(struct nl_msg *msg, void *arg);

  struct nl_cache*      m_cache_link;
  struct nl_cache_mngr* m_cache_link_mngr;

  static void cbCacheLinkInitial( struct nl_object*, void* );
  static void cbCacheLinkEvent1( struct nl_cache*, struct nl_object* obj, int, void* );
  static void cbCacheLinkEvent2(
      struct nl_cache*,
      struct nl_object* old_obj, struct nl_object* new_obj,
      uint64_t, int, void* );

  bool m_bPoll;
  std::thread m_threadPoll;
};

#endif /* APPFASTLANE_NETLINK_INTERFACE_H_ */
