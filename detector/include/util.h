#ifndef OONID_UTIL_H
#define OONID_UTIL_H

#include <tins/tins.h>
#include <cstdint>
extern "C" {
  #include <libnetfilter_queue/libnetfilter_queue.h>
}
#include "debug.h"

/**
 * Saves a connection (equality is independent of order of endpoints)
 * @param ip_a   first ip
 * @param port_a first port
 * @param ip_b   second_ip
 * @param port_b second port
 */
class Connection {
public:
  uint32_t ip_a;
  uint16_t port_a;
  uint32_t ip_b;
  uint16_t port_b;
  /**
   * Connections are equal if on of these conditions hold:
   * <ul>
   *  <li>ip_a1 == ip_a2 and ip_b1 == ip_b2 and port_a1 = port_a2 and port_b1 = port_b2</li>
   *  <li>ip_b1 == ip_a2 and ip_a1 == ip_b2 and port_b1 = port_a2 and port_a1 = port_b2</li>
   * </ul>
   * @param ip_a other connection
   */
  bool operator==(const Connection &other) const;
  /**
   * Saves a connection (equality is independent of order of endpoints)
   * @param ip_a   first ip
   * @param port_a first port
   * @param ip_b   second_ip
   * @param port_b second port
   */
  Connection(uint32_t ip_a, uint16_t port_a, uint32_t ip_b, uint16_t port_b)
    : ip_a(ip_a), port_a(port_a), ip_b(ip_b), port_b(port_b) {}
private:
  friend std::ostream& operator<< (std::ostream& os, const Connection& foo) {
      os << "(" << Tins::IPv4Address(foo.ip_a).to_string()
        << ":" << foo.port_a << " <-> " << Tins::IPv4Address(foo.ip_b).to_string()
        << ":" << foo.port_b << ")";
      return os;
  }
};

namespace std
{
  template<> struct hash<Connection>
  {
      size_t operator()(const Connection &k) const
      {
          return (size_t)(k.ip_a ^ (k.ip_b << 1) ^ (k.port_a << 2) ^ (k.port_b << 3));
      }
  };
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
