#include "queue/deny_dns.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>

extern "C" {
  #include <libnetfilter_queue/pktbuff.h>
  #include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
}

int DenyDnsQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  int verdict = NF_DROP;

  // Get payload of queue packet
  unsigned char *payload;
  std::cout << "getting payload" << std::endl;
  int psize = nfq_get_payload(nfad, &payload);

  std::cout << "got payload of size: " << psize << std::endl;

  // put it into packet buffer
  struct pkt_buff *packet = pktb_alloc(AF_INET, payload, psize, 0);

  // get ip header
  struct iphdr *ip_header = nfq_ip_get_hdr(packet);

  if(ip_header == NULL) {
    // Not an ip packet (or malformed)
    // is allowed
    verdict = NF_ACCEPT;
  } else {
    struct in_addr ip_src, ip_dst;
    ip_src.s_addr = ip_header->saddr;
    std::cout << "src addr set: " << inet_ntoa(ip_src) << std::endl;
    ip_dst.s_addr = ip_header->daddr;
    std::cout << "dst addr set: " << inet_ntoa(ip_dst) << std::endl;
    /* the std::string constructor is necessary so the result of inet_ntoa will be saved somewhere.
    inet_ntoa uses a static buffer, which would be overwritten on the second call */
    std::cout << std::string(inet_ntoa(ip_src)) << " -> " << std::string(inet_ntoa(ip_dst)) << std::endl;
  }

  // Packet buffer is not used anymore
  pktb_free(packet);

  verdict = NF_ACCEPT;

  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, verdict, 0, NULL);
}
