#include "queue/deny_dns.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <tins/tins.h>

extern "C" {
  #include <libnetfilter_queue/pktbuff.h>
}

using namespace Tins;

int DenyDnsQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  int verdict = NF_DROP;

  // Get payload of queue packet
  unsigned char *payload;
  int psize = nfq_get_payload(nfad, &payload);

  DEBUG("got payload of size: " << psize);

  try {
    /* Parse packet using tins */
    IP ip_packet(payload, psize);

    std::cout << ip_packet.src_addr().to_string() << " -> " << ip_packet.dst_addr().to_string() << std::endl;

    // check if udp - if yes try to parse as dns
    // if that succees -> drop the packet
    UDP *udp_packet = ip_packet.find_pdu<UDP>();
    if(udp_packet == NULL) {
      verdict = NF_ACCEPT;
      DEBUG("not and udp packet");
    } else {
      // get the - at this point - unparsed, inner pdu
      RawPDU *inner_pdu = udp_packet->find_pdu<RawPDU>();
      if(inner_pdu == NULL) {
        verdict = NF_ACCEPT;
      } else {
        try {
          DNS dns_packet = inner_pdu->to<DNS>();

          // converting succeeded - packet is dns - block it
          verdict = NF_DROP;

          DEBUG("blocking dns packet");
        } catch(malformed_packet e) {
          verdict = NF_ACCEPT;
          DEBUG("not a dns packet");
        }
      }
    }
  } catch(malformed_packet e) {
    // this is not an ip packet - do not block
    DEBUG("not an ip packet");
    verdict = NF_ACCEPT;
  }

  // set verdict
  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, verdict, 0, NULL);
}
