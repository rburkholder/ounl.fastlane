/*
 * Load.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Aug. 16, 2019
 */

#ifndef APPFASTLANE_BPF_USER_LOAD_H_
#define APPFASTLANE_BPF_USER_LOAD_H_

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

namespace asio = boost::asio;

class Load {
public:
  Load( asio::io_context& );
  ~Load();
protected:
private:
  bool m_bContinue;
  bool m_bFinished;
  asio::io_context& m_context;
  asio::steady_timer m_timer;

  void Start();
  void UpdateStats( const boost::system::error_code& );

};

#endif /* APPFASTLANE_BPF_USER_LOAD_H_ */
