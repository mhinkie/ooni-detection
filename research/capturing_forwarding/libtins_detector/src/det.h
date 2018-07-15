#ifndef DET_H
#define DET_H
/* configuration.h: Management of configuration instance */

#include <libconfig.h++>
#include <iostream>
#include <tins/tins.h>
#include <sstream>
#include <string>

/**
 * Router object is responsible of accepting pakets and routing them to the default gateway
 */
class Router {
  std::string if_internal, mac_internal, if_external, mac_external, def_gw_mac;
  Tins::Sniffer *sniffer;
public:
  Router(std::string if_internal, std::string mac_internal, std::string if_external, std::string mac_external, std::string def_gw_mac);
  void start();
  /** Handles packets from inside to outside */
  bool handleInternal(Tins::PDU&);
};


#endif
