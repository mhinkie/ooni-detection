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
#include "util.h"

using namespace Tins;

/**
 * returns the address for a hostname using getaddrinfo.<br />
 * address has to be deleted later.
 * @param  hostname
 * @return
 * @throws std::runtime_error on error
 */
IPv4Address *get_address(const std::string &hostname) {
  struct addrinfo *result;
  int error = getaddrinfo(hostname.c_str(), NULL, NULL, &result);
  if(!error) {
    IPv4Address *addr = new IPv4Address(((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr);
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
  std::vector<IPv4Address *> addresses;
  addresses.assign(std::begin(fb_servers), std::end(fb_servers));
  for_each(addresses.begin(), addresses.end(), [](IPv4Address *addr) {std::cout << addr->to_string() << std::endl;});
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
  /*
  std::find kann verwendet werden um ein element im array zu finden
  = ip-adressen array wird nach der destination adresse gescanned.
  wenn gefunden dann weiter mit klassifizierung
   */
  // Check if destination address is one of facebooks addresses
  //std::find(std::begin(this->fb_servers), std::end(this->fb_servers), )
  IP packet = parse_ip_packet(nfad);

  // find if returns a pointer to the result
  IPv4Address **contacted_server = std::find_if(
    std::begin(this->fb_servers),
    std::end(this->fb_servers),
    [&packet](const IPv4Address *addr){return *addr == packet.dst_addr();}
  );

  if(contacted_server != std::end(this->fb_servers)) {
    DEBUG("FB SERVER CONTACTED: " << **contacted_server);
    // Allow ping and tcp setup but deny everything above
    // TODO: detect tcp setup
  } else {
    // Not facebook server
  }


  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}
