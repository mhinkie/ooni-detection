#include "queue/detect_ooni/facebook_messenger.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <resolv.h>
#include <stdexcept>
#include <vector>
#include <algorithm>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

/**
 * returns the address for a hostname using getaddrinfo.<br />
 * address has to be deleted later.
 * @param  hostname
 * @return
 * @throws std::runtime_error on error
 */
Tins::IPv4Address *get_address(const std::string &hostname) {
  struct addrinfo *result;
  int error = getaddrinfo(hostname.c_str(), NULL, NULL, &result);
  if(!error) {
    Tins::IPv4Address *addr = new Tins::IPv4Address(((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr);
    freeaddrinfo(result);
    return addr;
  } else {
    throw std::runtime_error("Address could not be resolved for " + hostname);
  }
}

FBMessengerQueue::FBMessengerQueue(int queue_num) : StatusQueue(queue_num) {
  fb_servers[0] = get_address("star.c10r.facebook.com");
  fb_servers[1] = get_address("b-graph.facebook.com");
  fb_servers[2] = get_address("edge-mqtt.facebook.com");
  fb_servers[3] = get_address("external.xx.fbcdn.net");
  fb_servers[4] = get_address("scontent.xx.fbcdn.net");

  DEBUG("Resolved all facebook addresses");

  // OUTPUT
#ifndef NDEBUG
  std::vector<Tins::IPv4Address *> addresses;
  addresses.assign(std::begin(fb_servers), std::end(fb_servers));
  for_each(addresses.begin(), addresses.end(), [](Tins::IPv4Address *addr) {std::cout << addr->to_string() << std::endl;});
#endif
}

FBMessengerQueue::~FBMessengerQueue() {
  DEBUG("destroying fb messenger queue");

  // Release server addresses
  for(int i=0;i<5;i++) {
    delete this->fb_servers[i];
  }
}

int FBMessengerQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // accepting all
  std::cout << "accepting in fb queue" << std::endl;

  /*
  std::find kann verwendet werden um ein element im array zu finden
  = ip-adressen array wird nach der destination adresse gescanned.
  wenn gefunden dann weiter mit klassifizierung
   */

  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}
