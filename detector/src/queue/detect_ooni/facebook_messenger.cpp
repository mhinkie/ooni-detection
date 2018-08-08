#include "queue/detect_ooni/facebook_messenger.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <stdexcept>
#include <vector>
#include <algorithm>

using namespace Tins;

std::unordered_map<std::string, FBName> dname_name = {
  {"b-api.facebook.com", FBName::b_api},
  {"b-graph.facebook.com", FBName::b_graph},
  {"edge-mqtt.facebook.com", FBName::edge},
  {"external.xx.fbcdn.net", FBName::external_cdn},
  {"scontent.xx.fbcdn.net", FBName::scontent_cdn},
  {"star.c10r.facebook.com", FBName::star}
};

FBMessengerQueue::FBMessengerQueue(int queue_num) : IntegerStatusQueue(queue_num) {
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
    UDP *udp_pdu = packet.find_pdu<UDP>();
    if(udp_pdu != NULL) {
      // This is a dns request going out
      return this->handle_int_to_ext(queue, nfmsg, nfad, packet, udp_pdu);
    } else {
      // everything else is accepted
      ACCEPT_PACKET(queue, nfad);
    }
  }
}

int FBMessengerQueue::handle_ext_to_int(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  IP &packet,
  TCP *tcp_pdu) {

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
  UDP *udp_pdu) {

  // OONI will lookup the following addresses (in an undefined order)
  // if all requests were received the sending host will be marked as a probable probe
  /*
  'b_api': "b-api.facebook.com",
  'b_graph': "b-graph.facebook.com",
  'edge': "edge-mqtt.facebook.com",
  'external_cdn': "external.xx.fbcdn.net",
  'scontent_cdn': "scontent.xx.fbcdn.net",
  'star': "star.c10r.facebook.com" */

  // Ceck if this is a dns packet
  RawPDU *inner_pdu = udp_pdu->find_pdu<RawPDU>();
  if(inner_pdu != NULL) {
    try {
      DNS dns_pdu = inner_pdu->to<DNS>();

      // Converting succeeded
      DEBUG("got dns packet for inspection");
      // packet should be query
      if(dns_pdu.type() == DNS::QUERY) {
        std::vector<DNS::query> queries = dns_pdu.queries();
        if(queries.size() == 0) {
          DEBUG("no queries found!");
        } else {
          if(queries.size() > 1) {
            DEBUG("more than one query found - inspecting only the first");
          }

          DNS::query dns_query = queries[0];
          // lookup queried name to see if it is a facebook host
          try {
            FBName &facebook_server = dname_name.at(dns_query.dname());

            // Add to status for the sending host
          } catch(std::out_of_range e) {
            DEBUG("not a facebook host: " << dns_query.dname());
          }
        }
      } else {
        DEBUG("packet is not a query!");
      }

    } catch(malformed_packet e) {
      // Not dns = just accept
    }
  }

  ACCEPT_PACKET(queue, nfad);
}
