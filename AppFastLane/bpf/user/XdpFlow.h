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

class XdpFlow_impl;

class XdpFlow {
public:
  XdpFlow( asio::io_context& );
  ~XdpFlow();
protected:
private:

  asio::io_context& m_context;
  asio::steady_timer m_timer;

  size_t m_nLoops;

  std::unique_ptr<XdpFlow_impl> m_pXdpFlow_impl;

  void Start();
  void UpdateStats( const boost::system::error_code& );

};

#endif /* APPFASTLANE_BPF_USER_XDPFLOW_H_ */
