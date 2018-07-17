/**
 * Router implementation
 */
#ifndef ROUTER_H
#define ROUTER_H

#include <libconfig.h++>
#include <iostream>
#include <tins/tins.h>
#include <sstream>
#include <string>
#include <thread>
#include "det.h"

/**
 * Router object is responsible of accepting pakets and routing them to the default gateway
 */
class Router {
  std::string if_internal, mac_internal, if_external, mac_external, def_gw_mac, host_mac;
  Tins::Sniffer *internal_sniffer, *external_sniffer;
  Tins::PacketSender outgoing_sender, incoming_sender;
  Detector *detector;
public:
  Router(std::string if_internal, std::string mac_internal, std::string if_external, std::string mac_external, std::string def_gw_mac, std::string dst_network, std::string host_mac, Detector *detector);
  void start();
  /** Handles packets from inside to outside */
  bool handleInternal(Tins::PDU&);
  /** Handles packets from outside to inside */
  bool handleExternal(Tins::PDU&);
};


#endif
