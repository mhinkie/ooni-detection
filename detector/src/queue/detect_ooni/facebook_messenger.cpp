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

  TCP *tcp_pdu = packet.find_pdu<TCP>();

  // only check tcp packets
  if(tcp_pdu != NULL) {
    // find if returns a pointer to the result
    IPv4Address **int_to_ext = std::find_if(
      std::begin(this->fb_servers),
      std::end(this->fb_servers),
      [&packet](const IPv4Address *addr){return *addr == packet.dst_addr();}
    );

    // if not found, the result of std::find_if points to std::end
    if(int_to_ext != std::end(this->fb_servers)) {
      // This packet is going to facebook
      return this->handle_int_to_ext(queue, nfmsg, nfad, packet, tcp_pdu);
    } else {
      // Check if this packet is coming from facebook

      IPv4Address **ext_to_int = std::find_if(
        std::begin(this->fb_servers),
        std::end(this->fb_servers),
        [&packet](const IPv4Address *addr){return *addr == packet.src_addr();}
      );

      if(ext_to_int != std::end(this->fb_servers)) {
        // packet is coming from facebook
        return this->handle_ext_to_int(queue, nfmsg, nfad, packet, tcp_pdu);
      }
    }

  }

  // If nothing is done (not a facebook packet) - accept it
  ACCEPT_PACKET(queue, nfad);
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

  /*
  // There are 3 possiblities:
  //  - Packet is not part of tcp handshake -> BLOCK
  //  - Packet is SYN packet of tcp handshake -> ACCEPT and save
  //  - Packet is ACK packet of tcp handshake -> ACCEPT and remove status information
  if(tcp_pdu->get_flag(TCP::SYN)) {
    // Syn flag set - remember this connection
    Connection conn(packet.src_addr(), tcp_pdu->sport(), packet.dst_addr(), tcp_pdu->dport());
    if(this->connections.count(conn) > 0) {
      // Connection is already present = another syn received -> block packet
      // and delete connection
      this->connections.erase(conn);
      DEBUG("received second syn to " << packet.dst_addr().to_string() << " - blocking");
      DROP_PACKET(queue, nfad);
    } else {
      // Connection does not exist
      // create new one and accept
      this->connections[conn] = SYN;
      DEBUG("received syn to " << packet.dst_addr().to_string() << " - accepting");
      ACCEPT_PACKET(queue, nfad);
    }
  } else if(tcp_pdu->get_flag(TCP::ACK)) {
    Connection conn(packet.src_addr(), tcp_pdu->sport(), packet.dst_addr(), tcp_pdu->dport());
    this->connections.erase(conn);
    DEBUG("received ack to " << packet.dst_addr().to_string() << " - accepting");
    ACCEPT_PACKET(queue, nfad);
  } else {
  DEBUG("received something else to " << packet.dst_addr().to_string() << " - blocking");
    DROP_PACKET(queue, nfad);
  } */


}
