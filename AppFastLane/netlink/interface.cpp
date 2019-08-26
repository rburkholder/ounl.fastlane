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
#include <cassert>

#include "interface.h"

extern "C" {
#include <linux/if.h>
#include <linux/if_arp.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/link.h>
//lib/route/link.c - has the private stash of attribute decoding
//   is complicated, so revert to using the providing link caching routines
//   libnl/doc/api/lib_2route_2link_8c_source.html
}

int interface::cbCmd_Msg_Valid(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );

  // obtain message header
  struct nlmsghdr *hdr;
  hdr = nlmsg_hdr( msg );
  std::cout << "interface::cbCmd_Msg_Valid: " << std::endl;

  // content of message header
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

    // where the data resides
    void* data = nlmsg_data( hdr );
    void* tail = nlmsg_tail( hdr );
    int   len  = nlmsg_datalen( hdr );

    // because of the command sent, this is the message type to be expected
    ifinfomsg* hdr_rt = reinterpret_cast<ifinfomsg*>( data );

    char proto[ 64 ];
    nl_llproto2str( hdr_rt->ifi_type, proto, 64 );

    char flags[ 128 ];
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
        int remaining;
        //attr = nlmsg_attrdata( hdr, sizeof( ifinfomsg ) );
        //int len = nlmsg_attrlen( hdr, sizeof( ifinfomsg ) );
//        attr = nlmsg_attrdata( hdr, sizeof( ifinfomsg ) );
//        remaining = nlmsg_attrlen( hdr, sizeof( ifinfomsg ) );

//        while (nla_ok(attr, remaining)) {
//          std::cout
//            << "      attr: "
//            << "type=" << attr->nla_type
//            << ",len=" << attr->nla_len
//            << std::endl;
//          void* data = nla_data( attr );
//          switch ( attr->nla_type ) {
//            // attribute types are complicated for this message,
//            //   therefore reverting to use the link cache code
//          }
//          attr = nla_next(attr, &remaining);
//        };
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

void interface::cbCacheLinkInitial( struct nl_object* obj, void* data ) {
  interface* self = reinterpret_cast<interface*>( data );
  std::cout << "interface::cbCacheLinkInitial object: ";

  const char* sz;
  sz = nl_object_get_type( obj );
  assert( 0 != *sz );
  assert( 0 == strcmp( sz, "route/link") );

  struct rtnl_link* link = (struct rtnl_link *)obj;

  int ifindex = rtnl_link_get_ifindex( link );
  sz = rtnl_link_get_name( link );
  std::cout << ifindex << "=" << sz;

  std::cout << std::endl;
}

void interface::cbCacheLinkEvent1(
    struct nl_cache*,
    struct nl_object* obj,
    int action, // NL_ACT_*
    void* data
) {
  interface* self = reinterpret_cast<interface*>( data );
  std::cout << "interface::cbCacheLinkEvent1 action: ";
}

void interface::cbCacheLinkEvent2(
    struct nl_cache*,
    struct nl_object* old_obj, struct nl_object* new_obj,
    uint64_t, // result of nl_object_diff64
    int action, // NL_ACT_*
    void* data
) {
  interface* self = reinterpret_cast<interface*>( data );
  std::cout << "interface::cbCacheLinkEvent2 action: ";
  switch ( action ) {
    case NL_ACT_UNSPEC:
      std::cout << "unspec";
      break;
    case NL_ACT_NEW:
      std::cout << "new";
      break;
    case NL_ACT_DEL:
      std::cout << "del";
      break;
    case NL_ACT_GET:
      std::cout << "get";
      break;
    case NL_ACT_SET:
      std::cout << "set";
      break;
    case NL_ACT_CHANGE:
      std::cout << "change";
      break;
  }

  const char *szType;

  if ( nullptr != old_obj ) {
    szType = nl_object_get_type(old_obj);
    std::cout <<",old type='" << szType << "'";
    struct rtnl_link* link = (struct rtnl_link*)old_obj;
    int ifindex = rtnl_link_get_ifindex( link );
    std::cout << ",index=" << ifindex;
  }

  if ( nullptr != new_obj ) {
    szType = nl_object_get_type(new_obj);
    std::cout <<",new type='" << szType << "'";
    struct rtnl_link* link = (struct rtnl_link*)new_obj;
    int ifindex = rtnl_link_get_ifindex( link );
    std::cout << ",index=" << ifindex;
  }

  std::cout << std::endl;
}

interface::interface()
: m_bPoll( false )
{

  int status;

  // ====  cache manager for link information

  if ( false ) {
    //m_nl_sock_cache_link = nl_socket_alloc();
    //if ( nullptr == m_nl_sock_cache_link ) {
    //  throw std::runtime_error( "no netlink socket - m_nl_sock_cache_link" );
    //}

    //status = nl_connect(m_nl_sock_cache_link, NETLINK_ROUTE);

    status = nl_cache_mngr_alloc(nullptr, NETLINK_ROUTE, NL_AUTO_PROVIDE, &m_cache_link_mngr);
    //status = nl_cache_mngr_alloc(m_nl_sock_cache_link, NETLINK_ROUTE, NL_AUTO_PROVIDE, &m_cache_link_mngr);
    if ( 0 > status ) {
      throw std::runtime_error( "nl_cache_mngr_alloc failed" );
    }

    //status = rtnl_link_alloc_cache( m_nl_sock_cache_link, AF_UNSPEC, &m_cache_link );
    //if ( 0 > status ) {
    //  throw std::runtime_error( "cache issue - m_nl_sock_cache_link" );
    //}

    //status = nl_cache_mngr_add_cache_v2( m_cache_link_mngr, m_cache_link, &interface::cbCacheLinkEvent, this );
    //if ( 0 < status ) {
    //  throw std::runtime_error( "nl_cache_mngr_add_cache_v2 failed" );
    //}

    status = nl_cache_mngr_add(m_cache_link_mngr, "route/link", &interface::cbCacheLinkEvent1, this, &m_cache_link);
    if ( 0 > status ) {
      throw std::runtime_error( "nl_cache_mngr_add failed" );
    }

    nl_cache_foreach( m_cache_link, &interface::cbCacheLinkInitial, this );

    //struct nl_dump_params* params;
  }

  // ==== single message, with first message being link list

  if ( false ) { // initial message testing
    m_nl_sock_cmd = nl_socket_alloc();
    if ( nullptr == m_nl_sock_cmd ) {
      throw std::runtime_error( "no netlink socket - cmd" );
    }
    // auto ack set by default
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

  }

  // ==== single message, with attribute to request only interface statistics
  //    => can't seem to only get interface statistics

  if ( false ) {
    m_nl_sock_statistics = nl_socket_alloc();
    if ( nullptr == m_nl_sock_statistics ) {
      throw std::runtime_error( "no statistics socket" );
    }

    status = nl_socket_modify_cb( m_nl_sock_statistics, NL_CB_VALID, NL_CB_CUSTOM, &cbCmd_Msg_Valid, this);
    status = nl_socket_modify_cb( m_nl_sock_statistics, NL_CB_FINISH, NL_CB_CUSTOM, &cbCmd_Msg_Finished, this);
    status = nl_connect( m_nl_sock_statistics, NETLINK_ROUTE);

    struct nl_msg* msg;

    msg = nlmsg_alloc();
    //msg = nlmsg_alloc_simple( RTM_GETLINK, NLM_F_DUMP );
    if ( nullptr == msg ) {
      throw std::runtime_error( "no message allocated for statistics socket" );
    }

    struct nlmsghdr* hdr;
    hdr = nlmsg_put( msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETLINK, 0, NLM_F_DUMP );
    //hdr = nlmsg_put( msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_GETLINK, 0, 0 );

    struct ifinfomsg ifi = {
      .ifi_family = AF_UNSPEC,
      .ifi_index = 1
    };

    if ( 0 > nlmsg_append( msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) ) {
      throw std::runtime_error( "nnlmsg_append" );
    }

    struct rtgenmsg rt_hdr = {
      .rtgen_family = AF_UNSPEC,
    };

    //if ( 0 > nlmsg_append( msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO) ) {
    //  throw std::runtime_error( "nnlmsg_append" );
    //}

    struct nlattr* attr;
    //attr = nla_reserve( msg, IFLA_STATS, 0 );
    status = nla_put_flag( msg, IFLA_STATS );
    if ( 0 > status ) {
      throw std::runtime_error( "IFLA_STATS" );
    }

    status = nl_send_auto( m_nl_sock_statistics, msg );
    if ( 0 > status ) {
      std::cout << "m_nl_sock_statistics error: " << status << std::endl;
      throw std::runtime_error( "m_nl_sock_statistics error" );
    }

    nlmsg_free( msg );

    status = nl_recvmsgs_default(m_nl_sock_statistics);

  }

  // ==== disabled - listen for link changes, superseded by cache manager

  if ( false ) {
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
  }

  // ==== add thread for polling on sockets

  m_bPoll = true;
  m_threadPoll = std::move( std::thread(
    [this](){
      while ( m_bPoll ) {
        //int status = nl_cache_mngr_poll(m_cache_link_mngr, 500); //  ms
        //if ( 0 == status ) std::cout << "nl_cache_mngr_poll polling" << std::endl;
        //if ( 0 < status ) std::cout << "nl_cache_mngr_poll msgs=" << status << std::endl;
        //if ( 0 > status ) std::cout << "nl_cache_mngr_poll error=" << status << std::endl;
      }
    } ) );
}

interface::~interface() {

  m_bPoll = false;
  m_threadPoll.join();

  nl_cache_mngr_free( m_cache_link_mngr );
  nl_cache_free( m_cache_link );

  //int nl_socket_drop_memberships(struct nl_sock *sk, int group, ...);

  //nl_close( m_nl_sock_event );
  //nl_close( m_nl_sock_cmd );
  //nl_close( m_nl_sock_cache_link );
  nl_close( m_nl_sock_statistics );

  //nl_socket_free( m_nl_sock_event );
  //nl_socket_free( m_nl_sock_cmd );
  //nl_socket_free( m_nl_sock_cache_link );
  nl_socket_free( m_nl_sock_statistics );
}
