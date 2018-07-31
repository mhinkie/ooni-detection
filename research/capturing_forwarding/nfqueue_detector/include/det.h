/**
 * OONI Detector implementation using iptables nfqueue
 */
#ifndef DET_H
#define DET_H

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/**
 * Wrapper for netfilter queue to support automatic destroy
 */
class NFQueue {
  /* general handle for nfqueue - has to be deleted in the end */
  struct nfq_handle *handle;
  /* handle for the actual queue */
  struct nfq_q_handle *queue;
public:
  NFQueue(int queue_number);
  ~NFQueue();

  /** Handles packets (issues verdicts) for this queue */
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
  /** Starts processing */
  void start();
};

#endif
