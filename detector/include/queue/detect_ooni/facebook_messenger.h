#ifndef FACEBOOK_MESSENGER_H
#define FACEBOOK_MESSENGER_H

#include "queue/detect_ooni/status_queue.h"

/**
 * Queue implementation that blocks access to facebook messenger,
 * but circumvents OONI detection, meaning although access to facebook
 * messenger is blocked, OONI will think it is not blocked. <br />
 * This queue will keep status about hosts and is able to return if hosts
 * are suspected to be ooni probes.
 * @see StatusQueue
 */
class FBMessengerQueue : public StatusQueue {
public:
  FBMessengerQueue(int queue_num) : StatusQueue(queue_num) { }
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
};

#endif
