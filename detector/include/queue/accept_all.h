#ifndef ACCEPT_ALL_H
#define ACCEPT_ALL_H

#include "det.h"

/**
 * Queue implementation that accepts all packets.
 */
class AcceptAllQueue : public NFQueue {
public:
  AcceptAllQueue(int queue_num) : NFQueue(queue_num) { }
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
};

#endif
