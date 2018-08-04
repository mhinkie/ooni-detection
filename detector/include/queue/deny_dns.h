/**
 * Queue denying all dns
 */
#ifndef DENY_DNS_H
#define DENY_DNS_H

#include "det.h"

class DenyDnsQueue : public NFQueue {
public:
  DenyDnsQueue(int queue_num) : NFQueue(queue_num) { }
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
};

#endif
