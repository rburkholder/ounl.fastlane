/*
 * File:      log_syslog.h
 * Project:   OunlMessage
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 8, 2019
 */

#ifndef OUNLMESSAGE_LOG_SYSLOG_H_
#define OUNLMESSAGE_LOG_SYSLOG_H_

#include <string>

namespace ounl {
namespace log {

void init_native_syslog();
void init_builtin_syslog( const std::string& sSyslogServer);

} // namespace log
} // namespace ounl

#endif /* OUNLMESSAGE_LOG_SYSLOG_H_ */
