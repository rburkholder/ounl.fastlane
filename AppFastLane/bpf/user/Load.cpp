/*
 * Load.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created:   Aug. 16, 2019
 */

extern "C" {
#include <samples/bpf/bpf_load.h>
}

#include "Load.h"

Load::Load() {
  if ( 0 != load_bpf_file( (char*)"bpf/sock_stats.o" ) ) {
    //printf("The kernel didn't load the BPF program\\n");
  }

 read_trace_pipe();

}

Load::~Load() {
  // TODO Auto-generated destructor stub
}
