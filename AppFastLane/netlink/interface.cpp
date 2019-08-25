/*
 * File:      interface.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 24, 2019
 */

#include <stdexcept>
#include <iostream>

#include "interface.h"

extern "C" {
#include <netlink/netlink.h>
#include <netlink/msg.h>
//#include <netlink/route/link.h>
}

int interface::cbCmd(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );
  std::cout << "interface::dbCmd" << std::endl;

  struct nlmsghdr *hdr;
  //nlmsg_for_each(hdr, stream, length) {
          /* do something with message */
  //}

  return 0;
}

int interface::cbLinkEvent(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );
  std::cout << "interface::cbLinkEvent" << std::endl;
  return 0;
}

interface::interface() {

  int status;

  m_nl_sock_cmd = nl_socket_alloc();
  if ( nullptr == m_nl_sock_cmd ) {
    throw std::runtime_error( "no netlink socket - cmd" );
  }
  // auto ack by default
  //void nl_socket_enable_auto_ack(struct nl_sock *sk);
  //void nl_socket_disable_auto_ack(struct nl_sock *sk);
  status = nl_socket_modify_cb(m_nl_sock_cmd, NL_CB_VALID, NL_CB_CUSTOM, &cbCmd, this);
  status = nl_connect(m_nl_sock_cmd, NETLINK_ROUTE);

  struct rtgenmsg rt_hdr = {
    .rtgen_family = AF_UNSPEC,
  };
  status = nl_send_simple(m_nl_sock_cmd, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));

  //status = nl_socket_set_nonblocking(m_nl_sock_event); // poll returns immediately
  status = nl_recvmsgs_default(m_nl_sock_cmd);

  //struct nlmsghdr *hdr = stream;

  nl_close( m_nl_sock_cmd );

  // ====

  m_nl_sock_event = nl_socket_alloc();
  if ( nullptr == m_nl_sock_event ) {
    throw std::runtime_error( "no netlink socket - event" );
  }
  nl_socket_disable_seq_check(m_nl_sock_event);
  status = nl_socket_modify_cb(m_nl_sock_event, NL_CB_VALID, NL_CB_CUSTOM, &cbLinkEvent, this);
  status = nl_connect(m_nl_sock_event, NETLINK_ROUTE);
  //status = nl_socket_set_nonblocking(m_nl_sock_event); // poll returns immediately
  status = nl_socket_add_memberships(m_nl_sock_event, RTNLGRP_LINK, 0);

  //while (1)
    status = nl_recvmsgs_default(m_nl_sock_event);

  //int err = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &m_cache_mngr_link);
  //int status = nl_cache_mngr_add(m_cache_mngr_link, "route/link", nullptr, nullptr, &m_cache_link);

  //struct nl_dump_params* params;

  //if (nl_cache_mngr_poll(m_cache_mngr_link, 1000) > 0) {
  //        // Manager received at least one update, dump cache?
  //        nl_cache_dump(m_cache_link, params);
  //}
}

interface::~interface() {

  //nl_cache_mngr_free(m_cache_mngr_link);

  int nl_socket_drop_memberships(struct nl_sock *sk, int group, ...);

  nl_close( m_nl_sock_event );

  nl_socket_free( m_nl_sock_cmd );
  nl_socket_free( m_nl_sock_event );
}

