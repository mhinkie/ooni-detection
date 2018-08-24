#include "queue/detect_ooni/whatsapp.h"

WhatsappQueue::WhatsappQueue(int queue_num) : ExpiringQueue(queue_num, WHATSAPP_DESTINATION_COUNT, WHATSAPP_EXPIRY_TIME) {

}

WhatsappQueue::~WhatsappQueue() {
  TRACE("destroying whatsapp queue");
}


int WhatsappQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  TRACE("HANDLING PACKET");
}

/**
 * Handles packets coming from the inside network and going to a whatsapp server.
 * <b>This function should only receive DNS-request going out.</b>
 * DNS requests are monitor for detection purposes (no blocking will be performed).
 * @param  queue  The nfq_q_handle (for setting the verdict)
 * @param  nfmsg  The nfgenmsg
 * @param  nfad   The nfq_data in case of additional required parsing
 * @param  packet The ip-packet parsed using libtins.
 * @param  tcp_pdu A pointer to the tcp pdu of the given packet for convenience.
 * @return        Should return the return value of nfq_set_verdict (using makros ACCEPT_PACKET, DROP_PACKET)
 */
int handle_int_to_ext(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  Tins::IP &packet) {
  TRACE("int_to_ext");
}
