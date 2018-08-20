#include "queue/accept_all.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/netfilter.h>

int AcceptAllQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // accepting all
  TRACE("accepting");

  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}
