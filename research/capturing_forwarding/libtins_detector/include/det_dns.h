/**
 * Test-detector which drops all dns Packets
 */
#ifndef DET_DNS_H
#define DET_DNS_H

#include "det.h"
#include <tins/tins.h>

class DNSDetector : public Detector {
  bool process(const Tins::PDU &pdu);
};

#endif
