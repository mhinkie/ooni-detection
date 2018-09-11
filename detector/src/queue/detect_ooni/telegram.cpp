#include "queue/detect_ooni/telegram.h"
#include "protocol/tls.h"
#include "protocol/http.h"
#include "util.h"

#include <regex>
#include <stdexcept>

#define NUM_TELEGRAM_DESTINATIONS (ip_tname_http.size() + ip_tname_https.size() + 1) /* + web.telegram.org dns query */

using namespace Tins;

const std::regex TELEGRAM_MASK(".*\\.telegram\\.org");
const std::string TELEGRAM_WEB("web.telegram.org");

// Map ip to name of telegram destination (as specified in the ooni-test)
static std::unordered_map<IPv4Address, TelegramDestination> ip_tname_http = {
  {IPv4Address("149.154.175.50"), TelegramDestination::dc1_80},
  {IPv4Address("149.154.167.51"), TelegramDestination::dc2_80},
  {IPv4Address("149.154.175.100"), TelegramDestination::dc3_80},
  {IPv4Address("149.154.167.91"), TelegramDestination::dc4_80},
  {IPv4Address("149.154.171.5"), TelegramDestination::dc5_80}
};
static std::unordered_map<IPv4Address, TelegramDestination> ip_tname_https = {
  {IPv4Address("149.154.175.50"), TelegramDestination::dc1_443},
  {IPv4Address("149.154.167.51"), TelegramDestination::dc2_443},
  {IPv4Address("149.154.175.100"), TelegramDestination::dc3_443},
  {IPv4Address("149.154.167.91"), TelegramDestination::dc4_443},
  {IPv4Address("149.154.171.5"), TelegramDestination::dc5_443}
};

TelegramQueue::TelegramQueue(int queue_num) : ExpiringQueue(queue_num, NUM_TELEGRAM_DESTINATIONS, std::chrono::milliseconds {1000}) {

}

TelegramQueue::~TelegramQueue() {
  TRACE("destroying telegram queue");
}

int TelegramQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // Expects TCP to port 443
  IP packet = parse_ip_packet(nfad);
  TCP *tcp_pdu = packet.find_pdu<TCP>();

  if(tcp_pdu != NULL) {
    if(tcp_pdu->sport() == 443) {
      this->handle_incoming_tls(queue, nfmsg, nfad, packet, tcp_pdu);
    } else if(tcp_pdu->dport() == 80) {
      // coming from inside going to telegram
      this->handle_outgoing_http(queue, nfmsg, nfad, packet, tcp_pdu);
    } else if(tcp_pdu->dport() == 443) {
      // coming from inside goin to telegram via tls
      this->handle_outgoing_tls(queue, nfmsg, nfad, packet, tcp_pdu);
    } else {
      ACCEPT_PACKET(queue, nfad);
    }
  } else {
    // UDP?
    UDP *udp_pdu = packet.find_pdu<UDP>();
    if(udp_pdu != NULL && udp_pdu->sport() == 53) {
      // Dns reply
      this->handle_incoming_dns(queue, nfmsg, nfad, packet, udp_pdu);
    } else {
      ACCEPT_PACKET(queue, nfad);
    }
  }

  ACCEPT_PACKET(queue, nfad);
}

int TelegramQueue::handle_incoming_dns(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet,
  Tins::UDP *udp_pdu) {

  try {
    RawPDU *raw_pdu = udp_pdu->find_pdu<RawPDU>();
    if(raw_pdu != NULL) {
      DNS dns_pdu = raw_pdu->to<DNS>();

      if(dns_pdu.type() == DNS::RESPONSE && dns_pdu.answers_count() > 0) {
        std::vector<DNS::resource> answers = dns_pdu.answers();

        for(auto const& answer : answers) {
          if(answer.query_type() == DNS::A) {

            // Deny all tls except for telegram web
            if(answer.dname() != TELEGRAM_WEB && std::regex_match(answer.dname(), TELEGRAM_MASK)) {
              // is telegram server
              TRACE("got telegram server: " << answer.dname() << " - " << answer.data());
              this->blocked_ips.insert(IPv4Address(answer.data()));

              #ifdef ISTRACE
              TRACE("Blocked IPs:");
              for(auto const& ip : this->blocked_ips) {
                TRACE(ip);
              }
              #endif
            } else if(answer.dname() == TELEGRAM_WEB) {
              // Add telegram web to queried destinations
              TRACE("telegram web dns response found");
              this->add_queried_destination(TelegramDestination::web, packet.dst_addr());
            }
          }
        }
      } else {
        TRACE("no dns answers");
      }
    }
  } catch(malformed_packet e) {
    // Not dns = just accept
  }

  ACCEPT_PACKET(queue, nfad);
}


int TelegramQueue::handle_outgoing_tls(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet,
  Tins::TCP *tcp_pdu) {

  // check if this is a destination which should be marked
  try {
    const TelegramDestination &dest = ip_tname_https.at(packet.dst_addr());
    TRACE("adding https destination " << packet.dst_addr());
    this->add_queried_destination(dest, packet.src_addr());
  } catch(std::out_of_range e) {
    // if out of range is thrown it is not part of the telegram_dcs map
    // nothing to do here
  }

  if(this->blocked_ips.find(packet.dst_addr()) != this->blocked_ips.end()) {
    TRACE("BLOCKING " << packet.dst_addr());

    DROP_PACKET(queue, nfad);
  } else {
    TRACE("accepting other tls");
    ACCEPT_PACKET(queue, nfad);
  }
}


int TelegramQueue::handle_outgoing_http(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet,
  Tins::TCP *tcp_pdu) {
  TRACE("int to ext");

  if(tcp_pdu->dport() == 80) {
    // check if this is a destination which should be marked
    try {
      const TelegramDestination &dest = ip_tname_http.at(packet.dst_addr());
      TRACE("adding http destination " << packet.dst_addr());
      this->add_queried_destination(dest, packet.src_addr());
    } catch(std::out_of_range e) {
      // if out of range is thrown it is not part of the telegram_dcs map
      // nothing to do here
    }

    if(tcp_pdu->flags() == (TCP::PSH | TCP::ACK)) {
      TRACE("trying to convert");
      try {
        RawPDU *inner_pdu = tcp_pdu->find_pdu<RawPDU>();
        if(inner_pdu != NULL) {
          // Convert to http
          HTTP http_req = inner_pdu->to<HTTP>();

          // Accept if this is a post request to / - drop otherwise
          if(http_req.method() == HTTP::POST && (*http_req.location()) == "/") {
            TRACE("post to / found - accepting");
            ACCEPT_PACKET(queue, nfad);
          } else {
            TRACE("other http found - dropping (method: " << http_req.method() << ", location: " << (*http_req.location()) << ")");
            DROP_PACKET(queue, nfad);
          }
        }
      } catch(malformed_packet p) {
        TRACE("Not a valid http request");
      }
    } else {
      // Accept other tcp to allow handshake
      ACCEPT_PACKET(queue, nfad);
    }
  }

  DROP_PACKET(queue, nfad);

}

int TelegramQueue::handle_incoming_tls(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet,
  Tins::TCP *tcp_pdu) {
  // if this is port 443 - only allow tcp three way handshake (done by only allowing SYNACK and FINACK from server)
  if(tcp_pdu->sport() == 443) {
    if(tcp_pdu->flags() == (TCP::SYN | TCP::ACK)) {
      ACCEPT_PACKET(queue, nfad);
    }
    if(tcp_pdu->flags() == (TCP::FIN | TCP::ACK)) {
      ACCEPT_PACKET(queue, nfad);
    }
    TRACE("dropping 443 packet");
    DROP_PACKET(queue, nfad);
  } else {
    // Port 80
    ACCEPT_PACKET(queue, nfad);
  }
}
