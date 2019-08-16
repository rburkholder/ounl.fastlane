/* 
 * File:      ServerManager.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 201 Raymond Burkholder
 * Created:   2019/08/16 11:21
 * License:   GPL3
 */

#ifndef SERVERMANAGER_H
#define SERVERMANAGER_H

#include "Server.h"

class AppManager {
public:
  AppManager( int argc, char** argv );
  virtual ~AppManager( );
  void Start();
private:
  
  Server m_server;
  
};

#endif /* SERVERMANAGER_H */

