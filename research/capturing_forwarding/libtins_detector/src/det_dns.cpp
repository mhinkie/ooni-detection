#include "det_dns.h"

#include <iostream>

using namespace Tins;

bool DNSDetector::process(const PDU &pdu) {
  // Cannot ask directly for DNS-PDU because highler level
  // pdus are not always parsed
  const UDP *udp_pdu = pdu.find_pdu<UDP>();

  // If no dns pdu is found, 0 is returned
  if(udp_pdu == 0) {
    return true; //= accept
  } else {
    // try to convert this packet to dns
    // if that fails it is not DNS
    // if it succeeds it is dns and will be blocked
    const RawPDU *inner_pdu = udp_pdu->find_pdu<RawPDU>();
    if(inner_pdu == 0) {
      // should not happen, but if it does the packet will be forwarded (is not dns).
      return true;
    } else {
      try {
        DNS dns = inner_pdu->to<DNS>();
        // is dns
        return false;
      } catch(malformed_packet err) {
        // is not DNS
        return true;
      }
    }
  }
}
