#include "util.h"

Tins::IP parse_ip_packet(struct nfq_data *nfad) {
  // Get payload of queue packet
  unsigned char *payload;
  int psize = nfq_get_payload(nfad, &payload);

  Tins::IP ip_packet(payload, psize);
  return ip_packet;
}

bool Connection::operator==(const Connection &other) const {
  return
    (this->ip_a == other.ip_a && this->port_a == other.port_a && this->ip_b == other.ip_b && this->port_b == other.port_b) ||
    (this->ip_a == other.ip_b && this->port_a == other.port_b && this->ip_b == other.ip_a && this->port_b == other.port_a);
}
