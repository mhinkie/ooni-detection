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
  // No initialization required anymore because the queue can treat all
  // incoming packets as packets from facebook
}

FBMessengerQueue::~FBMessengerQueue() {
  DEBUG("destroying fb messenger queue");
}

int FBMessengerQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // only packets going from facebook to the local network are detected
  // becaus of iptables rules (so only handle_ext_to_int is used)
  IP packet = parse_ip_packet(nfad);

  TCP *tcp_pdu = packet.find_pdu<TCP>();

  if(tcp_pdu != NULL) {
    // only check TCP
    return this->handle_ext_to_int(queue, nfmsg, nfad, packet, tcp_pdu);
  } else {
    // everything else is accepted
    ACCEPT_PACKET(queue, nfad);
  }
}

int FBMessengerQueue::handle_ext_to_int(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  IP &packet,
  Tins::TCP *tcp_pdu) {

  // Only allow SYNACK and FINACK packets
  // packets for data transmission are not allowed
  if(tcp_pdu->flags() == (TCP::SYN | TCP::ACK)) {
    DEBUG("allowing SYNACK");
    ACCEPT_PACKET(queue, nfad);
  }
  if(tcp_pdu->flags() == (TCP::FIN | TCP::ACK)) {
    DEBUG("allowing FINACK");
    ACCEPT_PACKET(queue, nfad);
  }

  DEBUG("BLOCKING FACEBOOK PACKET");
  DROP_PACKET(queue, nfad);
}

int FBMessengerQueue::handle_int_to_ext(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  IP &packet,
  Tins::TCP *tcp_pdu) {

  ACCEPT_PACKET(queue, nfad);
}
