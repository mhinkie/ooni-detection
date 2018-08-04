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
private:
  /** saves the ips of the facebook servers in the right address (as they are connected to) */
  Tins::IPv4Address *fb_servers[5];
public:
  /**
   * Initializes the fb-messenger queue.
   * @param queue_num The number of this queue in iptables.
   * @throws std::runtime_error if not all facebook servers can be resolved.
   */
  FBMessengerQueue(int queue_num);
  virtual ~FBMessengerQueue();
  /**
   * Handles packets for facebook detection.<br />
   * OONI probes only check tcp-connection setup to see if facebook is reachable.
   * So the setup will be allowed to all servers, but all subsequent communication will be blocked.
   * <p>
   *  A host will be marked as an ooni-probe if this pattern of connection setups is detected:
   *  1 TCP to star.c10r.facebook.com
   *  2 TCP to b-graph.facebook.com
   *  3 TCP to edge-mqtt.facebook.com
   *  4 TCP to external.xx.fbcdn.net
   *  5 TCP to scontent.xx.fbcdn.net
   * @param  queue
   * @param  nfmsg
   * @param  nfad
   * @return
   */
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
};

#endif
