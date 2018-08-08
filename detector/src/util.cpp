#include "util.h"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdexcept>

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

Tins::IPv4Address *get_address(const std::string &hostname) {
  struct addrinfo *result;
  int error = getaddrinfo(hostname.c_str(), NULL, NULL, &result);
  if(!error) {
    Tins::IPv4Address *addr = new Tins::IPv4Address(((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr);
    freeaddrinfo(result);
    return addr;
  } else {
    throw std::runtime_error("Address could not be resolved for " + hostname);
  }
}
