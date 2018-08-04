#ifndef DET_H
#define DET_H

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

extern "C" {
  #include <libnetfilter_queue/libnetfilter_queue.h>
}

#ifndef NDEBUG
#define DEBUG(x) std::cout << x << std::endl
#else
#define DEBUG(x)
#endif

/**
 * OONI Detector implementation using iptables' nfqueue.
 * The NFQueue class can be extended to create packet filters. A NFQueue
 * has to provide a handle_pkt function which can parse the packet
 * and has to issue a verdict (DROP or ACCEPT) for each packet.
 */
class NFQueue {
  /** general handle for nfqueue - has to be destroyed in destructor */
  struct nfq_handle *handle;
  /** handle for the actual queue - has to be destroyed in destructor */
  struct nfq_q_handle *queue;
public:
  /**
   * Creates and initializes a new queue. The processing can be stated with start().
   * @param queue_number Queue number for this queue.
   */
  NFQueue(int queue_number);

  /**
   * Destroyes queue and releaseas all netfilter_queue resources.
   */
  virtual ~NFQueue();

  /**
   * Handles packets (issues verdicts) for this queue. <br />
   * Will be called once a packet for this queue is received (@see global_callback)
   * @param  queue
   * @param  nfmsg
   * @param  nfad
   * @return
   */
  virtual int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) = 0;

  /**
   * Starts queue processing: Receives packets and starts netfilter_queue handling.
   */
  void start();
};

#endif
