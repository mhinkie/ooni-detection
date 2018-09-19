#include "queue/detect_ooni/https_backend.h"
#include "util.h"

#include <regex>

#define NUM_HTTPS_BACKEND_STEPS 4

using namespace Tins;

const std::regex COLLECTOR_MASK(".*\\.collector\\.ooni\\.io");
const std::string BOUNCER("bouncer.ooni.io");


HTTPSBackendQueue::HTTPSBackendQueue(int queue_num) : ExpiringQueue(queue_num, NUM_HTTPS_BACKEND_STEPS, std::chrono::milliseconds {2000}) {

}

HTTPSBackendQueue::~HTTPSBackendQueue() {
  TRACE("destroying https-backend queue");
}


int HTTPSBackendQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // Expects TCP to port 443 or udp from port 53
  IP packet = parse_ip_packet(nfad);
  TCP *tcp_pdu = packet.find_pdu<TCP>();

  if(tcp_pdu != NULL) {
    if(tcp_pdu->dport() == 443) {
      this->handle_outgoing_tcp(queue, nfmsg, nfad, packet, tcp_pdu);
    }
  } else {
    // UDP?
    UDP *udp_pdu = packet.find_pdu<UDP>();
    if(udp_pdu != NULL && udp_pdu->sport() == 53) {
      // Dns reply
      this->handle_incoming_dns(queue, nfmsg, nfad, packet, udp_pdu);
    }
  }

  ACCEPT_PACKET(queue, nfad);
}


int HTTPSBackendQueue::handle_incoming_dns(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, Tins::IP &packet, Tins::UDP *udp_pdu) {

  RawPDU *raw_pdu = udp_pdu->find_pdu<RawPDU>();
  if(raw_pdu != NULL) {
    try {
      DNS dns_pdu = raw_pdu->to<DNS>();

      if(dns_pdu.type() == DNS::RESPONSE && dns_pdu.answers_count() > 0) {
        // Check if it contains an answer for bouncer or collector
        for(auto const& answer : dns_pdu.answers()) {
          if(answer.query_type() == DNS::A) {
            if(answer.dname() == BOUNCER) {
              this->bouncer_address = std::unique_ptr<IPv4Address>(new IPv4Address(answer.data()));
              TRACE("new bouncer address: " << *this->bouncer_address);

              // Add step to set of completed steps
              this->add_queried_destination(BackendStep::dns_bouncer, packet.dst_addr());
            } else if(std::regex_match(answer.dname(), COLLECTOR_MASK)) {
              this->collector_addresses.insert(IPv4Address(answer.data()));
              TRACE("collector answer found: " << answer.dname() << " - " << answer.data());

              this->add_queried_destination(BackendStep::dns_collector, packet.dst_addr());
            }
          }
        }
      }
    } catch(malformed_packet e) {
      // not dns
    }
  }

  ACCEPT_PACKET(queue, nfad);
}

int HTTPSBackendQueue::handle_outgoing_tcp(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, Tins::IP &packet, Tins::TCP *tcp_pdu) {
  if(tcp_pdu->flags() == TCP::SYN) {
    if(this->bouncer_address && packet.dst_addr() == *this->bouncer_address) {
      TRACE("bouncer tls");
    } else {
      if(this->collector_addresses.find(packet.dst_addr()) != this->collector_address.end()) {
        TRACE("collector tls");
      }
    }
  }

  ACCEPT_PACKET(queue, nfad);
}
