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
  m_pServer( dynamic_cast<Server*>( env.server() ) ),
  m_menuPersonal( nullptr ),
  m_cwContent( nullptr ),
  m_cwFooter( nullptr ),
  m_cwStatus( nullptr )
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

void AppFastLane::BuildInitialPage() {
  setCssTheme("polished");
  //useStyleSheet("resources/themes/bootstrap/3/less/normalize.less" ); // loaded automatically by bootstrap.css
  //useStyleSheet("resources/themes/bootstrap/3/less/navs.less" );
  //useStyleSheet("resources/themes/bootstrap/3/less/dropdowns.less" );
  useStyleSheet("resources/themes/bootstrap/3/bootstrap.css");
  useStyleSheet("resources/themes/bootstrap/3/wt.css");
  useStyleSheet("style/ounl.css");

  root()->clear();

}
