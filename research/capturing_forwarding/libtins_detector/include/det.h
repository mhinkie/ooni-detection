/*
 * Detector class
 * A detector is an object which provides a function to accept pdus,
 * and decide if they should be forwarded or not
 */

#ifndef DET_H
#define DET_H

#include <tins/tins.h>

class Detector {
public:
  /** Accepts a PDU and decides if it should be forwarded or not */
  virtual bool process(const Tins::PDU &pdu) = 0;
};

#endif
