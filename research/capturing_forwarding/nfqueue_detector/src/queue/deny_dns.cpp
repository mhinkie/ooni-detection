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

int DenyDnsQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  int verdict = NF_DROP;

  // Get payload of queue packet
  unsigned char *payload;
  std::cout << "getting payload" << std::endl;
  int psize = nfq_get_payload(nfad, &payload);

  std::cout << "got payload of size: " << psize << std::endl;

  try {
    /* Parse packet using tins */
    Tins::IP ip_packet(payload, psize);

    std::cout << ip_packet.src_addr().to_string() << " -> " << ip_packet.dst_addr().to_string() << std::endl;
  } catch(Tins::malformed_packet e) {
    // this is not an ip packet - do not block
    std::cout << "not an ip packet" << std::endl;
    verdict = NF_ACCEPT;
  }

  verdict = NF_ACCEPT;

  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, verdict, 0, NULL);
}
