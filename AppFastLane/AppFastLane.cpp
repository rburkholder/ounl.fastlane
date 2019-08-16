/*
 * AppFastLane.cpp
 *
 *  Created on: Aug. 16, 2019
 *      Author: rpb
 */

#include <boost/log/trivial.hpp>

#include "AppFastLane.h"

AppFastLane::AppFastLane( const Wt::WEnvironment& env )
: Wt::WApplication( env ),
  m_environment( env ),
  m_pServer( dynamic_cast<Server*>( env.server() ) )
{
}

AppFastLane::~AppFastLane() { }

void AppFastLane::initialize() {

  BOOST_LOG_TRIVIAL(info) << sessionId() << ",initialize()";

}

void AppFastLane::finalize() {
  BOOST_LOG_TRIVIAL(info) << sessionId() << ",finalize()";
  // TOOD: save time/date of last interaction?  or do on each page request?
  //SessionClose();
}

