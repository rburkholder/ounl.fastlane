/*
 * File:      ServerManager.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * Created:   2019/08/16 11:21
 * License:   GPL3
 */

#include <boost/log/trivial.hpp>

#include "AppFastLane.h"

#include "AppManager.h"

// =====

static std::unique_ptr<Wt::WApplication> CreateAppFastLane( const Wt::WEnvironment& env ) {
  //
  // Optionally, check the environment and redirect to an error page.
  //
  bool valid( true );
  std::unique_ptr<AppFastLane> app;
  if (!valid) {
    app = std::make_unique<AppFastLane>(env);
    app->redirect("error.html");
    app->quit();
  } else {
    app = std::make_unique<AppFastLane>(env);
  }
  return app;
}

// =====

AppManager::AppManager( int argc, char** argv )
: m_server( argc, argv )
{
    m_server.setServerConfiguration( argc, argv, WTHTTP_CONFIGURATION );
    m_server.addEntryPoint( Wt::EntryPointType::Application, CreateAppFastLane );
}

AppManager::~AppManager( ) { }

void AppManager::Start() {

  try {

    //UserAuth::configureAuth();

    if ( m_server.start() ) {
      Wt::WServer::waitForShutdown();
      m_server.stop();
    }

  }
  catch (Wt::WServer::Exception& e) {
    BOOST_LOG_TRIVIAL(trace) << "Wt exception:  " << e.what();
  }
  catch (std::exception &e) {
    BOOST_LOG_TRIVIAL(trace) << "std exception: " << e.what();
  }

  BOOST_LOG_TRIVIAL(trace) << "done.";

}
