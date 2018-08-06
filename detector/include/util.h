#ifndef OONID_UTIL_H
#define OONID_UTIL_H

#include <tins/tins.h>
extern "C" {
  #include <libnetfilter_queue/libnetfilter_queue.h>
}

/**
 * Sets the given verdict for this packet.
 * @param  queue   The queue which will accept or drop this packet.
 * @param  nfad    Packet data
 * @param  verdict The verdict.
 * @return         Returns the function with the result of nfq_set_verdict
 * @see ACCEPT_PACKET
 * @see DROP_PACKET
 */
#define SET_VERDICT(queue, nfad, verdict) { \
  struct nfqnl_msg_packet_hdr *ph; \
  ph = nfq_get_msg_packet_hdr((nfad)); \
  return nfq_set_verdict((queue), ntohl(ph->packet_id), (verdict), 0, NULL); \
}

/**
 * Sets the NF_ACCEPT verdict for the given packet.
 * @param  queue The queue which will accept the packet.
 * @param  nfad Packet data
 * @return      Returns the function with the result of nfq_set_verdict
 */
#define ACCEPT_PACKET(queue, nfad) SET_VERDICT((queue), (nfad), NF_ACCEPT)

/**
 * Sets the NF_DROP verdict for the given packet.
 * @param  queue The queue which will drop the packet.
 * @param  nfad Packet data
 * @return      Returns the function with the result of nfq_set_verdict
 */
#define DROP_PACKET(queue, nfad) SET_VERDICT((queue), (nfad), NF_DROP)

/**
 * Returns an IP pdu (libtins), parsed from the nfqueue packet data.
 * @param  nfad NFqueue packet data
 * @return      An IP Object parsed using libtins.
 * @throws  malformed_packet if this packet is not a valid ip packet
 */
Tins::IP parse_ip_packet(struct nfq_data *nfad);

#endif
