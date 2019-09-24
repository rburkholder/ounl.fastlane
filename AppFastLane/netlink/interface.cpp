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
//#include <unistd.h>
#include <cstring>

#include <boost/log/trivial.hpp>

#include <boost/asio/post.hpp>

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

void decodeMessageHeader( struct nlmsghdr *hdr ) {

  switch ( hdr->nlmsg_type ) {
    case RTM_NEWLINK:
      std::cout << "RTM_NEWLINK";
      break;
    case RTM_DELLINK:
      std::cout << "RTM_DELLINK";
      break;
    case RTM_GETLINK:
      std::cout << "RTM_GETLINK";
      break;
    case RTM_SETLINK:
      std::cout << "RTM_SETLINK";
      break;
    case RTM_NEWADDR:
      std::cout << "RTM_NEWADDR";
      break;
    case RTM_DELADDR:
      std::cout << "RTM_DELADDR";
      break;
    case RTM_GETADDR:
      std::cout << "RTM_GETADDR";
      break;
    case RTM_NEWROUTE:
      std::cout << "RTM_NEWROUTE";
      break;
    case RTM_DELROUTE:
      std::cout << "RTM_DELROUTE";
      break;
    case RTM_GETROUTE:
      std::cout << "RTM_GETROUTE";
      break;
    case RTM_NEWNEIGH:
      std::cout << "RTM_NEWNEIGH";
      break;
    case RTM_DELNEIGH:
      std::cout << "RTM_DELNEIGH";
      break;
    case RTM_GETNEIGH:
      std::cout << "RTM_GETNEIGH";
      break;
    case RTM_NEWRULE:
      std::cout << "RTM_NEWRULE";
      break;
    case RTM_DELRULE:
      std::cout << "RTM_DELRULE";
      break;
    case RTM_GETRULE:
      std::cout << "RTM_GETRULE";
      break;
    case RTM_NEWQDISC:
      std::cout << "RTM_NEWQDISC";
      break;
    case RTM_DELQDISC:
      std::cout << "RTM_DELQDISC";
      break;
    case RTM_GETQDISC:
      std::cout << "RTM_GETQDISC";
      break;
    case RTM_NEWTCLASS:
      std::cout << "RTM_NEWTCLASS";
      break;
    case RTM_DELTCLASS:
      std::cout << "RTM_DELTCLASS";
      break;
    case RTM_GETTCLASS:
      std::cout << "RTM_GETTCLASS";
      break;
    case RTM_NEWTFILTER:
      std::cout << "RTM_NEWTFILTER";
      break;
    case RTM_DELTFILTER:
      std::cout << "RTM_DELTFILTER";
      break;
    case RTM_GETTFILTER:
      std::cout << "RTM_GETTFILTER";
      break;
    default:
      std::cout << "RTM_?? UNKNOWN(" << hdr->nlmsg_type << ")";
      break;
  }

  std::cout
    << ",len=" << hdr->nlmsg_len
    << ",flags=" << std::hex << hdr->nlmsg_flags << std::dec // 2=NLM_F_MULTI
    << ",seq=" << hdr->nlmsg_seq
    << ",pid=" << hdr->nlmsg_pid
    << std::endl;
}

void decode_ifinfomsg( ifinfomsg* ifinfo ) {

  char proto[ 64 ];
  nl_llproto2str( ifinfo->ifi_type, proto, 64 );

  char flags[ 128 ];
  rtnl_link_flags2str(ifinfo->ifi_flags, flags, 128);

  std::cout
    << "    family=" << (unsigned)ifinfo->ifi_family
    << ",type=" << proto
    << ",index=" << ifinfo->ifi_index
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
    << std::endl;

}

int interface::cbCmd_Msg_LinkInitial( struct nl_msg* msg, void* arg ) {

  interface* self = reinterpret_cast<interface*>( arg );
  //std::cout << "interface::cbCmd_Msg_LinkInitial: " << std::endl;

  struct nlmsghdr *hdr = nullptr;
  hdr = nlmsg_hdr( msg );

  link_t linkInfo;

  // content of message header
  int length( hdr->nlmsg_len );
  while (nlmsg_ok(hdr, length)) {

    //decodeMessageHeader( hdr );

    // where the data resides
    void* data = nlmsg_data( hdr );
    void* tail = nlmsg_tail( hdr );
    int   len  = nlmsg_datalen( hdr );

    // because of the command sent, this is the message type to be expected
    ifinfomsg* ifinfo = reinterpret_cast<ifinfomsg*>( data );

    linkInfo.if_index = ifinfo->ifi_index;

    linkInfo.bUp      = ( IFF_UP       & ifinfo->ifi_flags );
    linkInfo.bLowerUp = ( IFF_LOWER_UP & ifinfo->ifi_flags );
    linkInfo.bRunning = ( IFF_RUNNING  & ifinfo->ifi_flags );

    switch ( ifinfo->ifi_type ) {
      case ARPHRD_LOOPBACK:
        linkInfo.bLoopback = true;
        break;
      case ARPHRD_ETHER:
        linkInfo.bEthernet = true;
        break;
    }

    assert( RTM_NEWLINK == hdr->nlmsg_type );

    struct nlattr* attr;
    attr = nlmsg_attrdata( hdr, sizeof( ifinfomsg ) );

    int remaining;
    remaining = nlmsg_attrlen( hdr, sizeof( ifinfomsg ) );

    struct rtnl_link_stats64 stats64;

    while (nla_ok(attr, remaining)) {
      void* data = nla_data( attr );
      switch ( attr->nla_type ) {
        case IFLA_IFNAME:
          linkInfo.if_name = (char*)data;
          break;
        case IFLA_STATS64:
          // need to copy because structure is 4 byte aligned, not 8 byte aligned
          memcpy( &stats64, (struct rtnl_link_stats64*)data, sizeof( struct rtnl_link_stats64 ) );
          break;
        case IFLA_ADDRESS:
          if ( linkInfo.bEthernet || linkInfo.bLoopback ) {
            for ( int ix = 0; ix++; ix < 6 ) linkInfo.mac[ ix ] = ((uint8_t*)data)[ ix ];
          }
          break;
        case IFLA_BROADCAST:
          if ( linkInfo.bEthernet || linkInfo.bLoopback ) {
            for ( int ix = 0; ix++; ix < 6 ) linkInfo.broadcast[ ix ] = ((uint8_t*)data)[ ix ];
          }
          break;
        case IFLA_QDISC:
          linkInfo.qdisk = (char*)data;
          break;
        default:
          //std::cout << "        " << attr->nla_type << " size=" << attr->nla_len << std::endl;
          break;
      }
      attr = nla_next(attr, &remaining);
    };

    if ( nullptr != self->m_fLinkInitial ) self->m_fLinkInitial( std::move( linkInfo ), std::move( stats64 ) );

    hdr = nlmsg_next(hdr, &length);
  }

  return NL_OK;
}

// TODO: redo this, and remove a bunch of link code?
int interface::cbCmd_Msg_LinkChanges( struct nl_msg* msg, void* arg ) {

  interface* self = reinterpret_cast<interface*>( arg );
  BOOST_LOG_TRIVIAL(trace) << "interface::cbCmd_Msg_LinkDelta: ";

  struct nlmsghdr *hdr = nlmsg_hdr( msg );

  link_t linkInfo;

  // content of message header
  int length( hdr->nlmsg_len );
  while (nlmsg_ok(hdr, length)) {

    //decodeMessageHeader( hdr );

    // where the data resides
    void* data = nlmsg_data( hdr );
    void* tail = nlmsg_tail( hdr );
    int   len  = nlmsg_datalen( hdr );

    // because of the command sent, this is the message type to be expected
    ifinfomsg* ifinfo = reinterpret_cast<ifinfomsg*>( data );
    decode_ifinfomsg( ifinfo );

    linkInfo.if_index = ifinfo->ifi_index;

    linkInfo.bUp      = ( IFF_UP       & ifinfo->ifi_flags );
    linkInfo.bLowerUp = ( IFF_LOWER_UP & ifinfo->ifi_flags );
    linkInfo.bRunning = ( IFF_RUNNING  & ifinfo->ifi_flags );

    switch ( ifinfo->ifi_type ) {
      case ARPHRD_LOOPBACK:
        linkInfo.bLoopback = true;
        break;
      case ARPHRD_ETHER:
        linkInfo.bEthernet = true;
        break;
    }

    struct nlattr* attr;
    attr = nlmsg_attrdata( hdr, sizeof( ifinfomsg ) );

    int remaining;
    remaining = nlmsg_attrlen( hdr, sizeof( ifinfomsg ) );

    struct rtnl_link_stats64 stats64;

    switch( hdr->nlmsg_type ) {
      case RTM_NEWLINK:
        while (nla_ok(attr, remaining)) {
          void* data = nla_data( attr );
          switch ( attr->nla_type ) {
            case IFLA_IFNAME:
              //BOOST_LOG_TRIVIAL(trace) << "        IFLA_IFNAME=" << (char*)nla_data(attr);
              linkInfo.if_name = (char*)data;
              break;
            case IFLA_STATS64:
              // need to copy because structure is 4 byte aligned, not 8 byte aligned
              memcpy( &stats64, (struct rtnl_link_stats64*)data, sizeof( struct rtnl_link_stats64 ) );
              break;
            case IFLA_ADDRESS:
              if ( linkInfo.bEthernet || linkInfo.bLoopback ) {
                for ( int ix = 0; ix++; ix < 6 ) linkInfo.mac[ ix ] = ((uint8_t*)data)[ ix ];
              }
              break;
            case IFLA_BROADCAST:
              if ( linkInfo.bEthernet || linkInfo.bLoopback ) {
                for ( int ix = 0; ix++; ix < 6 ) linkInfo.broadcast[ ix ] = ((uint8_t*)data)[ ix ];
              }
              break;
            case IFLA_QDISC:
              linkInfo.qdisk = (char*)data;
              break;
            default:
              //std::cout << "        " << attr->nla_type << " size=" << attr->nla_len << std::endl;
              //BOOST_LOG_TRIVIAL(trace)
              //  << "      attr: "
              //  << "type=" << attr->nla_type
              //  << ",len=" << attr->nla_len
              //    ;
              break;
          }
          attr = nla_next(attr, &remaining);
        };

        //if ( nullptr != self->m_fLinkInitial ) self->m_fLinkInitial( std::move( linkInfo ), std::move( stats64 ) );
        if ( nullptr != self->m_fLinkStats ) self->m_fLinkStats( ifinfo->ifi_index, stats64 );
        break;
      case RTM_DELLINK:
        // TODO: test what happens when loopback created in namespace
        // TOOD: test what happens as veth moved in and out of namespace
        break;
    }

    hdr = nlmsg_next(hdr, &length);
  }

  return NL_OK;
}

int interface::cbCmd_Msg_LinkStats( struct nl_msg* msg, void* arg ) {
  interface* self = reinterpret_cast<interface*>( arg );
  std::cout << "interface::cbCmd_Msg_LinkStats: " << std::endl;

  struct nlmsghdr *hdr;
  hdr = nlmsg_hdr( msg );

  // content of message header
  int length( hdr->nlmsg_len );
  while (nlmsg_ok(hdr, length)) {

    // where the data resides
    void* data = nlmsg_data( hdr );
    //void* tail = nlmsg_tail( hdr );
    //int   len  = nlmsg_datalen( hdr );

    // because of the command sent, this is the message type to be expected
    ifinfomsg* ifinfo = reinterpret_cast<ifinfomsg*>( data );

    //assert( RTM_NEWLINK == hdr->nlmsg_type );

    struct nlattr* attr;
    attr = nlmsg_attrdata( hdr, sizeof( ifinfomsg ) );

    int remaining;
    remaining = nlmsg_attrlen( hdr, sizeof( ifinfomsg ) );

    struct rtnl_link_stats64 stats64;

    while (nla_ok(attr, remaining)) {
      if ( IFLA_STATS64 == attr->nla_type ) {
        // need to copy because structure is 4 byte aligned, not 8 byte aligned
        memcpy( &stats64, (struct rtnl_link_stats64*)(nla_data( attr )), sizeof( struct rtnl_link_stats64 ) );
        if ( nullptr != self->m_fLinkStats ) {
          self->m_fLinkStats( ifinfo->ifi_index, stats64 );
        }
        break;
      }

      attr = nla_next(attr, &remaining);
    };
    hdr = nlmsg_next(hdr, &length);
  }

  return NL_OK;
}

int interface::cbCmd_Msg_Finished(struct nl_msg *msg, void *arg) {
  interface* self = reinterpret_cast<interface*>( arg );
  //BOOST_LOG_TRIVIAL(trace) << "interface::cbCmd_Msg_Finished" << std::endl;

  struct nlmsghdr *hdr;
  //nlmsg_for_each(hdr, stream, length) {
          /* do something with message */
  //}

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
  BOOST_LOG_TRIVIAL(trace) << ifindex << "=" << sz;

}

void interface::cbCacheLinkEvent1(
    struct nl_cache*,
    struct nl_object* obj,
    int action, // NL_ACT_*
    void* data
) {
  interface* self = reinterpret_cast<interface*>( data );

  const char *szType;

  std::cout << "interface::cbCacheLinkEvent1 action: ";

  szType = nl_object_get_type(obj);
  std::cout <<",new type='" << szType << "'";
  struct rtnl_link* link = (struct rtnl_link*)obj;
  int ifindex = rtnl_link_get_ifindex( link );
  BOOST_LOG_TRIVIAL(trace) << ",index=" << ifindex;

}

void interface::cbCacheLinkEvent2(
    struct nl_cache*,
    struct nl_object* old_obj, struct nl_object* new_obj,
    uint64_t, // result of nl_object_diff64
    int action, // NL_ACT_*
    void* data
) {
  interface* self = reinterpret_cast<interface*>( data );
  //BOOST_LOG_TRIVIAL(trace) <<"interface::cbCacheLinkEvent2 action: ";
  switch ( action ) {
    case NL_ACT_UNSPEC:
      //std::cout << "unspec";
      break;
    case NL_ACT_NEW:
      //std::cout << "new";
      break;
    case NL_ACT_DEL:
      //std::cout << "del";
      break;
    case NL_ACT_GET:
      //std::cout << "get";
      break;
    case NL_ACT_SET:
      //std::cout << "set";
      break;
    case NL_ACT_CHANGE:
      //std::cout << "change";
      break;
  }

  const char *szType;

  if ( nullptr != old_obj ) {
    szType = nl_object_get_type(old_obj);
    //std::cout <<",old type='" << szType << "'";
    struct rtnl_link* link = (struct rtnl_link*)old_obj;
    int ifindex = rtnl_link_get_ifindex( link );
    //std::cout << ",index=" << ifindex;
  }

  if ( nullptr != new_obj ) {
    szType = nl_object_get_type(new_obj);
    //std::cout <<",new type='" << szType << "'";
    struct rtnl_link* link = (struct rtnl_link*)new_obj;
    int ifindex = rtnl_link_get_ifindex( link );
    //std::cout << ",index=" << ifindex;
  }

  //std::cout << std::endl;
}

interface::interface( asio::io_context& context, fLinkInitial_t&& fLinkInitial, fLinkStats_t&& fLinkStats )
: m_ePoll(EPoll::Quiescent), m_cntLoops(10 )
 ,m_context( context )
 ,m_strand( m_context )
 ,m_timer( m_context )
 ,m_fLinkInitial( std::move( fLinkInitial ) )
 ,m_fLinkStats( std::move( fLinkStats ) )
{

  int status;

  // ==== single message, with first message being link list

  if ( true ) {
    m_nl_sock_cmd = nl_socket_alloc();
    if ( nullptr == m_nl_sock_cmd ) {
      throw std::runtime_error( "no netlink socket - cmd" );
    }
    // auto ack set by default
    //void nl_socket_enable_auto_ack(struct nl_sock *sk);
    //void nl_socket_disable_auto_ack(struct nl_sock *sk);
    status = nl_socket_modify_cb(m_nl_sock_cmd, NL_CB_VALID, NL_CB_CUSTOM, &cbCmd_Msg_LinkInitial, this);
    status = nl_socket_modify_cb(m_nl_sock_cmd, NL_CB_FINISH, NL_CB_CUSTOM, &cbCmd_Msg_Finished, this);
    status = nl_connect(m_nl_sock_cmd, NETLINK_ROUTE);
    status = nl_socket_set_nonblocking(m_nl_sock_cmd); // poll returns immediately

    struct rtgenmsg rt_hdr = {
      .rtgen_family = AF_UNSPEC,
    };
    status = nl_send_simple(m_nl_sock_cmd, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));

  }

  // ==== listen for link changes, comes after the dump above so can do delta's against the list

  if ( true ) {

    m_nl_sock_event = nl_socket_alloc();
    if ( nullptr == m_nl_sock_event ) {
      throw std::runtime_error( "no netlink socket - event" );
    }

    nl_socket_disable_seq_check(m_nl_sock_event);
    status = nl_socket_modify_cb(m_nl_sock_event, NL_CB_VALID, NL_CB_CUSTOM, &cbCmd_Msg_LinkChanges, this);
    status = nl_connect(m_nl_sock_event, NETLINK_ROUTE);
    status = nl_socket_set_nonblocking(m_nl_sock_event); // poll returns immediately
    status = nl_socket_add_memberships(m_nl_sock_event, RTNLGRP_LINK, 0);
    status = nl_socket_add_memberships(m_nl_sock_event, RTNLGRP_IPV4_IFADDR, 0);
    status = nl_socket_add_memberships(m_nl_sock_event, RTNLGRP_IPV6_IFADDR, 0);

  }

  // ====  cache manager for link information

  if ( false ) {
    // doesn't generate callbacks when statistics are requested

    m_nl_sock_cache_link = nl_socket_alloc();
    if ( nullptr == m_nl_sock_cache_link ) {
      throw std::runtime_error( "no netlink socket - m_nl_sock_cache_link" );
    }

    // is over-written or ignored:
    //status = nl_socket_modify_cb(m_nl_sock_cache_link, NL_CB_VALID, NL_CB_CUSTOM, &interface::cbCmd_Msg_Valid, this);

    // generates socket error:
    //status = nl_connect(m_nl_sock_cache_link, NETLINK_ROUTE);

    //status = nl_cache_mngr_alloc(nullptr, NETLINK_ROUTE, NL_AUTO_PROVIDE, &m_cache_link_mngr);
    status = nl_cache_mngr_alloc(m_nl_sock_cache_link, NETLINK_ROUTE, NL_AUTO_PROVIDE, &m_cache_link_mngr);
    if ( 0 > status ) {
      BOOST_LOG_TRIVIAL(trace) << "nl_cache_mngr_alloc error " << status << std::endl;
      // TODO: need to free the socket
      throw std::runtime_error( "nl_cache_mngr_alloc failed" );
    }

    //status = rtnl_link_alloc_cache( m_nl_sock_cache_link, AF_UNSPEC, &m_cache_link );
    //if ( 0 > status ) {
    //  std::cout << "rtnl_link_alloc_cache error " << status << std::endl;
    //  throw std::runtime_error( "cache issue - m_nl_sock_cache_link" );
    //}

    status = nl_cache_mngr_add_cache_v2( m_cache_link_mngr, m_cache_link, &interface::cbCacheLinkEvent2, this );
    if ( 0 > status ) {
      BOOST_LOG_TRIVIAL(trace) << "nl_cache_mngr_add_cache_v2 error " << status << std::endl;
      // TODO: need to free socket and cache
      throw std::runtime_error( "nl_cache_mngr_add_cache_v2 failed" );
    }

    status = nl_cache_mngr_add(m_cache_link_mngr, "route/link", &interface::cbCacheLinkEvent1, this, &m_cache_link);
    if ( 0 > status ) {
      BOOST_LOG_TRIVIAL(trace) << "nl_cache_mngr_add error " << status << std::endl;
      throw std::runtime_error( "nl_cache_mngr_add failed" );
    }

    nl_cache_foreach( m_cache_link, &interface::cbCacheLinkInitial, this );

    //struct nl_dump_params* params;
  }

  // ==== single message, with attribute to request only interface statistics
  //    => can't seem to only get interface statistics

  if ( false ) {
    m_nl_sock_statistics = nl_socket_alloc();
    if ( nullptr == m_nl_sock_statistics ) {
      throw std::runtime_error( "no statistics socket" );
    }

    status = nl_socket_modify_cb( m_nl_sock_statistics, NL_CB_VALID, NL_CB_CUSTOM, &cbCmd_Msg_LinkChanges, this);
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

    //struct rtgenmsg rt_hdr = {
    //  .rtgen_family = AF_UNSPEC,
    //};

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
      BOOST_LOG_TRIVIAL(trace) << "m_nl_sock_statistics error: " << status << std::endl;
      throw std::runtime_error( "m_nl_sock_statistics error" );
    }

    nlmsg_free( msg );

    status = nl_recvmsgs_default(m_nl_sock_statistics);

  }

  // ==== add thread for polling on sockets

  m_ePoll = EPoll::Running;
  asio::post( m_strand, std::bind( &interface::Poll, this ) );

}

void interface::Poll() {
    //int status = nl_cache_mngr_poll(m_cache_link_mngr, 500); //  ms
    //if ( 0 == status ) std::cout << "nl_cache_mngr_poll polling" << std::endl;
    //if ( 0 < status ) std::cout << "poll msgs=" << status << std::endl;
    //if ( 0 > status ) std::cout << "poll error=" << status << std::endl;
  switch ( m_ePoll ) {
    case EPoll::Quiescent:
      break;
    case EPoll::Running:
    {
      m_timer.expires_after( std::chrono::milliseconds( 200 ) );
      m_timer.async_wait(
        [this](const boost::system::error_code& error){
          int status;
          if ( error || (EPoll::Stop == m_ePoll ) ) {
            m_ePoll = EPoll::Stopped;
          }
          else {

            static struct rtgenmsg rt_hdr = {
              .rtgen_family = AF_UNSPEC,
            };

            m_cntLoops--;
            if ( 0 == m_cntLoops ) {
            //  status = nl_send_simple(m_nl_sock_cache_link, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
              status = nl_send_simple(m_nl_sock_cmd, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
              m_cntLoops = 10;
            }

            asio::post( m_strand, std::bind( &interface::Poll, this ) );
          }

          // TODO: change from polling to blocking mode and assign a thread per block and post message
          //    to a main processing thread (strand) for synchronization?
          status = nl_recvmsgs_default(m_nl_sock_event);
          status = nl_recvmsgs_default(m_nl_sock_cmd);
        });
      }
      break;
    case EPoll::Stop:
    {
      int status;
      status = nl_recvmsgs_default(m_nl_sock_event);
      status = nl_recvmsgs_default(m_nl_sock_cmd);
      m_ePoll = EPoll::Stopped;
      }
      break;
    case EPoll::Stopped:
      break;
  }
}

interface::~interface() {

  m_ePoll = EPoll::Stop;
  m_timer.cancel();
  while (EPoll::Stopped != m_ePoll );  // will this run forever?

  //nl_cache_mngr_free( m_cache_link_mngr );
  //nl_cache_free( m_cache_link );

  //int nl_socket_drop_memberships(struct nl_sock *sk, int group, ...);

  nl_close( m_nl_sock_event );
  nl_close( m_nl_sock_cmd );
  //nl_close( m_nl_sock_cache_link );
  //nl_close( m_nl_sock_statistics );

  nl_socket_free( m_nl_sock_event );
  nl_socket_free( m_nl_sock_cmd );
  //nl_socket_free( m_nl_sock_cache_link );
  //nl_socket_free( m_nl_sock_statistics );
}
