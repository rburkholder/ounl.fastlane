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

#include <functional>

extern "C" {
#include <netlink/socket.h>
//#include <netlink/cache.h>
}

class interface {
public:
  interface();
  ~interface();
protected:
private:
  struct nl_sock* m_nl_sock_cmd;
  struct nl_sock* m_nl_sock_event;

  using fNetlinkCallBack_t = std::function<int(struct nl*, void*)>;

  static fNetlinkCallBack_t m_fNetlinkCallBack;
  static int cbCmd(struct nl_msg *msg, void *arg);
  static int cbLinkEvent(struct nl_msg *msg, void *arg);

  //struct nl_cache_mngr* m_cache_mngr_link;
  //struct nl_cache*      m_cache_link;
};

#endif /* APPFASTLANE_NETLINK_INTERFACE_H_ */
