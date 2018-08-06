#include "util.h"

Tins::IP parse_ip_packet(struct nfq_data *nfad) {
  // Get payload of queue packet
  unsigned char *payload;
  int psize = nfq_get_payload(nfad, &payload);

  Tins::IP ip_packet(payload, psize);
  return ip_packet;
}
