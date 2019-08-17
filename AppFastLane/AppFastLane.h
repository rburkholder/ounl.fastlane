/*
 * AppFastLane.h
 *
 *  Created on: Aug. 16, 2019
 *      Author: rpb
 */

#ifndef APPFASTLANE_APPFASTLANE_H_
#define APPFASTLANE_APPFASTLANE_H_

#include <Wt/WEnvironment.h>
#include <Wt/WApplication.h>

#include <Wt/WContainerWidget.h>
#include <Wt/WMenu.h>

#include "Server.h"

class AppFastLane: public Wt::WApplication {
public:

  AppFastLane( const Wt::WEnvironment& );
  virtual ~AppFastLane();

  virtual void initialize( void ); // Initializes the application, post-construction.
  virtual void finalize( void ); // Finalizes the application, pre-destruction.

private:

  const Wt::WEnvironment& m_environment;
  Server* m_pServer; // object managed by wt

  Wt::WMenu* m_menuPersonal;
  Wt::WContainerWidget* m_cwContent;
  Wt::WContainerWidget* m_cwFooter;
  Wt::WContainerWidget* m_cwStatus;  // to be implemented as part of cwFooter.

  void BuildInitialPage();

};

#endif /* APPFASTLANE_APPFASTLANE_H_ */
