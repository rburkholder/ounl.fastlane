/*
 * File:      XdpFlow.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Sep. 5, 2019
 */

#ifndef APPFASTLANE_BPF_USER_XDPFLOW_H_
#define APPFASTLANE_BPF_USER_XDPFLOW_H_

#include <functional>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

namespace asio = boost::asio;

class XdpFlow {
public:
  XdpFlow( asio::io_context& );
  ~XdpFlow();
protected:
private:

  int m_mapMac_fd;
  int m_mapProtocol_fd;
  int m_mapIpv4_fd;

  asio::io_context& m_context;
  asio::steady_timer m_timer;

  int m_if_index;

  size_t m_nLoops;

  void Start();
  void UpdateStats( const boost::system::error_code& );

};

#endif /* APPFASTLANE_BPF_USER_XDPFLOW_H_ */
