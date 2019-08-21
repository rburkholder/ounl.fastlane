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

#include <functional>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

namespace asio = boost::asio;

class Load {
public:

  using fUpdateData_t = std::function<void(long long, long long, long long)>;

  Load( asio::io_context&, fUpdateData_t&& );
  ~Load();
protected:
private:

  bool m_bContinue;
  bool m_bFinished;
  bool m_bFirst;

  long long m_llTcp;
  long long m_llUdp;
  long long m_llIcmp;

  asio::io_context& m_context;
  asio::steady_timer m_timer;

  fUpdateData_t m_fUpdateData;

  void Start();
  void UpdateStats( const boost::system::error_code& );

};

#endif /* APPFASTLANE_BPF_USER_LOAD_H_ */
