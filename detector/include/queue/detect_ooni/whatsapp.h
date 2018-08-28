#ifndef WHATSAPP_H
#define WHATSAPP_H

#include "queue/detect_ooni/expiring_queue.h"

#define WHATSAPP_EXPIRATION_TIME std::chrono::milliseconds {1000}
#define WHATSAPP_DESTINATION_COUNT 3


enum class WhatsappDestination {v, eX, web};

// Hash for FBName
namespace std {
  template<> struct hash<WhatsappDestination> {
      size_t operator()(const WhatsappDestination &name) const {
          return (size_t)name;
      }
  };
}

/**
 * Queue implementation that blocks access to whatsapp web.
 * It detects whatsapp by listening for dns queries. After all
 * required dns queries are found the host is marked as a probe and
 * access to whatsapp web is allowed.
 * <p>
 *  Will only handle IPv4 for the moment.
 * </p>
 * @see StatusQueue
 */
class WhatsappQueue : public ExpiringQueue<WhatsappDestination> {
private:

  /**
   * Handles packets coming from the inside network and going to a whatsapp server.
   * <b>This function should only receive DNS-request going out.</b>
   * DNS requests are monitor for detection purposes (no blocking will be performed).
   * @param  queue  The nfq_q_handle (for setting the verdict)
   * @param  nfmsg  The nfgenmsg
   * @param  nfad   The nfq_data in case of additional required parsing
   * @param  packet The ip-packet parsed using libtins.
   * @param  udp_pdu A pointer to the udp pdu of the given packet for convenience.
   * @return        Should return the return value of nfq_set_verdict (using makros ACCEPT_PACKET, DROP_PACKET)
   */
  int handle_int_to_ext(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::UDP *udp_pdu);

  /**
   * Handles packets coming from the outside network (whatsapp servers).
   * These packets will be blocked when the receiving host is not a ooni-probe.
   * @param  queue  The nfq_q_handle (for setting the verdict)
   * @param  nfmsg  The nfgenmsg
   * @param  nfad   The nfq_data in case of additional required parsing
   * @param  packet The ip-packet parsed using libtins.
   * @param  tcp_pdu A pointer to the tcp pdu of the given packet for convenience.
   * @return        Should return the return value of nfq_set_verdict (using makros ACCEPT_PACKET, DROP_PACKET)
   */
  int handle_ext_to_int(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::TCP *tcp_pdu);

public:

  /**
   * Initializes the fb-messenger queue.
   * @param queue_num The number of this queue in iptables.
   * @throws std::runtime_error if not all facebook servers can be resolved.
   */
  WhatsappQueue(int queue_num);
  virtual ~WhatsappQueue();
  /**
   * Handles packets for facebook detection.<br />
   * OONI probes only check tcp-connection setup to see if facebook is reachable.
   * So the setup will be allowed to all servers, but all subsequent communication will be blocked.
   * @param  queue
   * @param  nfmsg
   * @param  nfad
   * @return
   */
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);

};

#endif
