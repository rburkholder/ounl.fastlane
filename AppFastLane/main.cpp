/*
 * File:      main.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * Created:   2019/08/16 11:21
 * License:   GPL3
 */

#include "AppManager.h"

// http://www.webtoolkit.eu/wt/doc/reference/html/InstallationUnix.html
// https://www.webtoolkit.eu/wt/doc/reference/html/overview.html

// mkdir -p ounl.fastlane/x64/web/resources
// mkdir -p ounl.fastlane/x64/web/style

// cp -r ../libs-build/wt/resources web/
// cp -p /etc/wt/wt_config.xml ounl.web/x64/etc/

int main( int argc, char** argv ) {

  //bool bOk( false );

  //try {
  //  bOk = true;
  //}
  //catch(...) {
  //  std::cout << "can not make connection to database" << std::endl;
  //}

  //if ( bOk ) {

  AppManager manager( argc, argv ); // might want a pool of message channels to backend
  manager.Start();

  //}

  return 0;
}
