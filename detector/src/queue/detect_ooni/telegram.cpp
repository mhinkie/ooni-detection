#include "queue/detect_ooni/telegram.h"
#include "protocol/tls.h"
#include "protocol/http.h"
#include "util.h"

using namespace Tins;

TelegramQueue::TelegramQueue(int queue_num) : ExpiringQueue(queue_num, 2, std::chrono::milliseconds {1000}) {

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
    } else {
      ACCEPT_PACKET(queue, nfad);
    }
  } else {
    ACCEPT_PACKET(queue, nfad);
  }

  ACCEPT_PACKET(queue, nfad);
}

int TelegramQueue::handle_outgoing_http(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet,
  Tins::TCP *tcp_pdu) {
  TRACE("int to ext");

  if(tcp_pdu->dport() == 80) {
    if(tcp_pdu->flags() == (TCP::PSH | TCP::ACK)) {
      TRACE("trying to convert");
      try {
        RawPDU *inner_pdu = tcp_pdu->find_pdu<RawPDU>();
        if(inner_pdu != NULL) {
          // Convert to http
          HTTP http_req = inner_pdu->to<HTTP>();
        }
      } catch(malformed_packet p) {
        TRACE("Not a valid http request");
      }
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
