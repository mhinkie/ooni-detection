#include "queue/detect_ooni/whatsapp.h"
#include "util.h"

using namespace Tins;

/** Associates whatsapp domains with WhatsappDestination values */
static std::unordered_map<std::string, WhatsappDestination> dname_name = {
  {"v.whatsapp.net", WhatsappDestination::v},
  {"e1.whatsapp.net", WhatsappDestination::eX},
  {"e2.whatsapp.net", WhatsappDestination::eX},
  {"e3.whatsapp.net", WhatsappDestination::eX},
  {"e4.whatsapp.net", WhatsappDestination::eX},
  {"e5.whatsapp.net", WhatsappDestination::eX},
  {"e6.whatsapp.net", WhatsappDestination::eX},
  {"e7.whatsapp.net", WhatsappDestination::eX},
  {"e8.whatsapp.net", WhatsappDestination::eX},
  {"e9.whatsapp.net", WhatsappDestination::eX},
  {"e10.whatsapp.net", WhatsappDestination::eX},
  {"e11.whatsapp.net", WhatsappDestination::eX},
  {"e12.whatsapp.net", WhatsappDestination::eX},
  {"e13.whatsapp.net", WhatsappDestination::eX},
  {"e14.whatsapp.net", WhatsappDestination::eX},
  {"e15.whatsapp.net", WhatsappDestination::eX},
  {"e16.whatsapp.net", WhatsappDestination::eX},
  {"e17.whatsapp.net", WhatsappDestination::eX},
  {"web.whatsapp.com", WhatsappDestination::web}
};

WhatsappQueue::WhatsappQueue(int queue_num) : ExpiringQueue(queue_num, WHATSAPP_DESTINATION_COUNT, WHATSAPP_EXPIRATION_TIME) {

}

WhatsappQueue::~WhatsappQueue() {
  TRACE("destroying whatsapp queue");
}


int WhatsappQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  TRACE("HANDLING PACKET");
  // Only ip packets are received - this should not fail
  IP packet = parse_ip_packet(nfad);

  // UDP Packets are treated as int_to_ext (dns requests)
  // TCP Packets are treated as ext_to_int (whatsapp traffic)

  UDP *udp_pdu = packet.find_pdu<UDP>();

  if(udp_pdu != NULL) {
    return handle_int_to_ext(queue, nfmsg, nfad, packet, udp_pdu);
  } else {
    TCP *tcp_pdu = packet.find_pdu<TCP>();
    if(tcp_pdu != NULL) {
      return handle_ext_to_int(queue, nfmsg, nfad, packet, tcp_pdu);
    } else {
      // Something else - accepting
      ACCEPT_PACKET(queue, nfad);
    }
  }
}

int WhatsappQueue::handle_ext_to_int(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet,
  TCP *tcp_pdu) {
    
  //block for hosts that are not marked as probes
  if(this->is_probe(packet.dst_addr())) {
    TRACE("PROBE - ACCEPTING");
    ACCEPT_PACKET(queue, nfad);
  } else {
    TRACE("NOT A PROBE - DROPPING");
    DROP_PACKET(queue, nfad);
  }
}

/**
 * Handles packets coming from the inside network and going to a whatsapp server.
 * <b>This function should only receive DNS-request going out.</b>
 * DNS requests are monitor for detection purposes (no blocking will be performed).
 * @param  queue  The nfq_q_handle (for setting the verdict)
 * @param  nfmsg  The nfgenmsg
 * @param  nfad   The nfq_data in case of additional required parsing
 * @param  packet The ip-packet parsed using libtins.
 * @param  tcp_pdu A pointer to the tcp pdu of the given packet for convenience.
 * @return        Should return the return value of nfq_set_verdict (using makros ACCEPT_PACKET, DROP_PACKET)
 */
int WhatsappQueue::handle_int_to_ext(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  IP &packet,
  UDP *udp_pdu) {

  TRACE("int_to_ext");
    // This is a dns request going out
  RawPDU *inner_pdu = udp_pdu->find_pdu<RawPDU>();
  if(inner_pdu != NULL) {
    try {
      DNS dns_pdu = inner_pdu->to<DNS>();

      // Converting succeeded
      TRACE("inspecting dns");
      // packet should be query
      if(dns_pdu.type() == DNS::QUERY) {
        std::vector<DNS::query> queries = dns_pdu.queries();
        if(queries.size() == 0) {
          TRACE("no queries found!");
        } else {
          if(queries.size() > 1) {
            TRACE("more than one query found - inspecting only the first");
          }

          DNS::query dns_query = queries[0];
          // lookup queried name to see if it is a facebook host
          try {
            WhatsappDestination &whatsapp_dest = dname_name.at(dns_query.dname());

            TRACE("found whatsapp name " << dns_query.dname());

            // Add to set of already found destinations
            this->add_queried_destination(whatsapp_dest, packet.src_addr());
          } catch(std::out_of_range e) {
            TRACE("not a whatsapp host: " << dns_query.dname());
          }
        }
      } else {
        TRACE("not a query!");
      }
    } catch(malformed_packet e) {
      // Not dns = just accept
    }
  }
  ACCEPT_PACKET(queue, nfad);

}
