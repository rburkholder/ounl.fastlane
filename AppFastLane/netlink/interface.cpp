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
#include <ios>

#include "interface.h"

extern "C" {
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <linux/if_arp.h>
#include <netlink/utils.h>
#include <linux/if.h>
#include <netlink/route/link.h>
}

int interface::cbCmd_Msg_Valid(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );

  struct nlmsghdr *hdr;
  hdr = nlmsg_hdr( msg );
  std::cout << "interface::cbCmd_Msg_Valid: " << std::endl;

  int length( hdr->nlmsg_len );
  while (nlmsg_ok(hdr, length)) {
    std::cout
      << "  len=" << hdr->nlmsg_len
      //<< ",type=" << hdr->nlmsg_type
      << ",";
    if ( RTM_NEWLINK == hdr->nlmsg_type ) std::cout << "RTM_NEWLINK";
    if ( RTM_DELLINK == hdr->nlmsg_type ) std::cout << "RTM_DELLINK";
    if ( RTM_GETLINK == hdr->nlmsg_type ) std::cout << "RTM_GETLINK";
    if ( RTM_SETLINK == hdr->nlmsg_type ) std::cout << "RTM_SETLINK";
    if ( RTM_NEWADDR == hdr->nlmsg_type ) std::cout << "RTM_NEWADDR";
    if ( RTM_DELADDR == hdr->nlmsg_type ) std::cout << "RTM_DELADDR";
    if ( RTM_GETADDR == hdr->nlmsg_type ) std::cout << "RTM_GETADDR";
    if ( RTM_NEWROUTE == hdr->nlmsg_type ) std::cout << "RTM_NEWROUTE";
    if ( RTM_DELROUTE == hdr->nlmsg_type ) std::cout << "RTM_DELROUTE";
    if ( RTM_GETROUTE == hdr->nlmsg_type ) std::cout << "RTM_GETROUTE";
    if ( RTM_NEWNEIGH == hdr->nlmsg_type ) std::cout << "RTM_NEWNEIGH";
    if ( RTM_DELNEIGH == hdr->nlmsg_type ) std::cout << "RTM_DELNEIGH";
    if ( RTM_GETNEIGH == hdr->nlmsg_type ) std::cout << "RTM_GETNEIGH";
    if ( RTM_NEWRULE == hdr->nlmsg_type ) std::cout << "RTM_NEWRULE";
    if ( RTM_DELRULE == hdr->nlmsg_type ) std::cout << "RTM_DELRULE";
    if ( RTM_GETRULE == hdr->nlmsg_type ) std::cout << "RTM_GETRULE";
    if ( RTM_NEWQDISC == hdr->nlmsg_type ) std::cout << "RTM_NEWQDISC";
    if ( RTM_DELQDISC == hdr->nlmsg_type ) std::cout << "RTM_DELQDISC";
    if ( RTM_GETQDISC == hdr->nlmsg_type ) std::cout << "RTM_GETQDISC";
    if ( RTM_NEWTCLASS == hdr->nlmsg_type ) std::cout << "RTM_NEWTCLASS";
    if ( RTM_DELTCLASS == hdr->nlmsg_type ) std::cout << "RTM_DELTCLASS";
    if ( RTM_GETTCLASS == hdr->nlmsg_type ) std::cout << "RTM_GETTCLASS";
    if ( RTM_NEWTFILTER == hdr->nlmsg_type ) std::cout << "RTM_NEWTFILTER";
    if ( RTM_DELTFILTER == hdr->nlmsg_type ) std::cout << "RTM_DELTFILTER";
    if ( RTM_GETTFILTER == hdr->nlmsg_type ) std::cout << "RTM_GETTFILTER";

    std::cout
      << ",flags=" << std::hex << hdr->nlmsg_flags << std::dec
      << ",seq=" << hdr->nlmsg_seq
      << ",pid=" << hdr->nlmsg_pid
      << std::endl;

    void* data = nlmsg_data( hdr );
    void* tail = nlmsg_tail( hdr );
    int   len  = nlmsg_datalen( hdr );


    ifinfomsg* hdr_rt = reinterpret_cast<ifinfomsg*>( data );

    char proto[ 64 ];
    nl_llproto2str( hdr_rt->ifi_type, proto, 64 );

    char flags[ 64 ];
    rtnl_link_flags2str(hdr_rt->ifi_flags, flags, 64);

    std::cout
      << "    family=" << (unsigned)hdr_rt->ifi_family
      << ",type=" << proto
      << ",index=" << hdr_rt->ifi_index
      << ",flags=" << flags
//      << ",change=" << hdr_rt->ifi_change
    //if ( IFF_UP & hdr_rt->ifi_flags ) std::cout << ",up";
    //if ( IFF_BROADCAST & hdr_rt->ifi_flags ) std::cout << ",broadcast";
    //if ( IFF_DEBUG & hdr_rt->ifi_flags ) std::cout << ",debug";
    //if ( IFF_LOOPBACK & hdr_rt->ifi_flags ) std::cout << ",loopback";
    //if ( IFF_POINTOPOINT & hdr_rt->ifi_flags ) std::cout << ",pt2pt";
    //if ( IFF_NOTRAILERS & hdr_rt->ifi_flags ) std::cout << ",no_trailers";
    //if ( IFF_RUNNING & hdr_rt->ifi_flags ) std::cout << ",running";
    //if ( IFF_NOARP & hdr_rt->ifi_flags ) std::cout << ",no_arp";
    //if ( IFF_PROMISC & hdr_rt->ifi_flags ) std::cout << ",promisc";
    //if ( IFF_ALLMULTI & hdr_rt->ifi_flags ) std::cout << ",all_multi";
    //if ( IFF_MASTER & hdr_rt->ifi_flags ) std::cout << ",master";
    //if ( IFF_SLAVE & hdr_rt->ifi_flags ) std::cout << ",slave";
    //if ( IFF_MULTICAST & hdr_rt->ifi_flags ) std::cout << ",multicast";
    //if ( IFF_PORTSEL & hdr_rt->ifi_flags ) std::cout << ",portsel";
    //if ( IFF_AUTOMEDIA & hdr_rt->ifi_flags ) std::cout << ",auto_media";
    //if ( IFF_DYNAMIC & hdr_rt->ifi_flags ) std::cout << ",dynamic";
    //if ( IFF_LOWER_UP & hdr_rt->ifi_flags ) std::cout << ",lower_up";
    //if ( IFF_DORMANT & hdr_rt->ifi_flags ) std::cout << ",dormant";
    //if ( IFF_ECHO & hdr_rt->ifi_flags ) std::cout << ",echo";
    //std::cout
      << std::endl;

    switch ( hdr->nlmsg_type ) {
      case RTM_NEWLINK: {
        struct nlattr* attr;
        attr = nlmsg_attrdata( hdr, sizeof( ifinfomsg ) );
        int len = nlmsg_attrlen( hdr, sizeof( ifinfomsg ) );
        }
        break;
    }

    hdr = nlmsg_next(hdr, &length);
  }

  return NL_OK;
}

int interface::cbCmd_Msg_Finished(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );
  std::cout << "interface::cbCmd_Msg_Finished" << std::endl;

  struct nlmsghdr *hdr;
  //nlmsg_for_each(hdr, stream, length) {
          /* do something with message */
  //}

  return NL_OK;
}

int interface::cbLinkEvent(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );
  std::cout << "interface::cbLinkEvent" << std::endl;
  return NL_OK;
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
  status = nl_socket_modify_cb(m_nl_sock_cmd, NL_CB_VALID, NL_CB_CUSTOM, &cbCmd_Msg_Valid, this);
  status = nl_socket_modify_cb(m_nl_sock_cmd, NL_CB_FINISH, NL_CB_CUSTOM, &cbCmd_Msg_Finished, this);
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
