/**
 * Utility functions for ooni-detector (packet parsing and more)
 */
#ifndef OONID_UTIL_H
#define OONID_UTIL_H

#include <tins/tins.h>
extern "C" {
  #include <libnetfilter_queue/libnetfilter_queue.h>
}

/**
 * Returns an IP pdu (libtins), parsed from the nfqueue packet data.
 * @param  nfad NFqueue packet data
 * @return      An IP Object parsed using libtins.
 * @throws  malformed_packet if this packet is not a valid ip packet
 */
Tins::IP parse_ip_packet(struct nfq_data *nfad);

#endif
