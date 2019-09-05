/*
 * RawSocket.cpp
 *
 *  Created on: Sep. 5, 2019
 *      Author: rpb
 */

#include <sstream>
#include <stdexcept>

#include "RawSocket.h"

extern "C" {
//#include <stdlib.h>
//#include <stdio.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
}

int open_raw_sock( int if_index ) {

  struct sockaddr_ll sll;
  int sock;

  sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (sock < 0) {
    throw std::runtime_error("cannot create raw socket");
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_index;
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    close(sock);
    std::stringstream ss;
    ss << "error on bind to " << if_index << ": " << strerror( errno );
    throw std::runtime_error( ss.str() );
  }

  return sock;
}

