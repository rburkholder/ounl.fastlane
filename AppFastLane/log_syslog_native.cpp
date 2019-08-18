/*
 * File:      log_syslog_native.cpp
 * Project:   OunlMessage
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 8, 2019
 */

#include "log_syslog.h"

#define BOOST_LOG_USE_NATIVE_SYSLOG

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

void init_native_syslog() {
  boost::shared_ptr< logging::core > core = logging::core::get();

  // Create a backend
  boost::shared_ptr< sinks::syslog_backend > backend(new sinks::syslog_backend(
      keywords::facility = sinks::syslog::user,
      keywords::use_impl = sinks::syslog::native
  ));

  // Set the straightforward level translator for the "Severity" attribute of type int
  backend->set_severity_mapper(sinks::syslog::direct_severity_mapping< int >("Severity"));

  // Wrap it into the frontend and register in the core.
  // The backend requires synchronization in the frontend.
  core->add_sink(boost::make_shared< sink_t >(backend));
}

} // namespace log
} // namespace ounl



