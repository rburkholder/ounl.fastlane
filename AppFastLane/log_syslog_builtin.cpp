/*
 * File:      log_syslog_builtin.cpp
 * Project:   OunlMessage
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 8, 2019
 */

#include "log_syslog.h"

#include <boost/log/trivial.hpp>
#include <boost/log/common.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/syslog_backend.hpp>

namespace logging = boost::log;
namespace attrs = boost::log::attributes;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;
namespace keywords = boost::log::keywords;
//https://www.boost.org/doc/libs/1_69_0/libs/log/doc/html/log/detailed/sink_backends.html#log.detailed.sink_backends.syslog
//~/data/projects/libs-build/boost_1_69_0/libs/log/example/syslog/main.cpp

namespace ounl {
namespace log {

using sink_t = sinks::synchronous_sink< sinks::syslog_backend >;

void init_builtin_syslog( const std::string& sSyslogServer) {

  boost::shared_ptr< logging::core > core = logging::core::get();

  // Create a new backend
  boost::shared_ptr< sinks::syslog_backend > backend(new sinks::syslog_backend(
      keywords::facility = sinks::syslog::local0,
      keywords::use_impl = sinks::syslog::udp_socket_based
  ));

  // Setup the target address and port to send syslog messages to
  backend->set_target_address(sSyslogServer, 514);

  // Create and fill in another level translator for "MyLevel" attribute of type string
  sinks::syslog::custom_severity_mapping< std::string > mapping("app_blgc");

  mapping["debug"] = sinks::syslog::debug;
  mapping["normal"] = sinks::syslog::info;
  mapping["warning"] = sinks::syslog::warning;
  mapping["failure"] = sinks::syslog::critical;

  mapping["info"] = sinks::syslog::info;
  mapping["error"] = sinks::syslog::critical;
  mapping["trace"] = sinks::syslog::debug;

  backend->set_severity_mapper(mapping);

  // Wrap it into the frontend and register in the core.
  core->add_sink(boost::make_shared< sink_t >(backend));
}

} // namespace log
} // namespace ounl





