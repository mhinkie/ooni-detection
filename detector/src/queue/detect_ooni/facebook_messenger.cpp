#include "queue/detect_ooni/facebook_messenger.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <resolv.h>
#include <stdexcept>
#include <vector>
#include <algorithm>

using namespace Tins;

FBMessengerQueue::FBMessengerQueue(int queue_num) : StatusQueue(queue_num) {
  // No initialization required anymore because the queue can treat all
  // incoming packets as packets from facebook
  //   fb_servers[0] = get_address("star.c10r.facebook.com");
  fb_servers[1] = get_address("b-graph.facebook.com");
  fb_servers[2] = get_address("edge-mqtt.facebook.com");
  fb_servers[3] = get_address("external.xx.fbcdn.net");
  fb_servers[4] = get_address("scontent.xx.fbcdn.net");

  DEBUG("Resolved all facebook addresses");

  // OUTPUT
#ifdef ISDEBUG
  std::vector<Tins::IPv4Address *> addresses;
  addresses.assign(fb_servers, fb_servers + 5);
  for_each(addresses.begin(), addresses.end(), [](Tins::IPv4Address *addr) { DEBUG(addr->to_string());});
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
