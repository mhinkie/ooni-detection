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
  std::string if_internal;
  std::string mac_internal;
  Tins::Sniffer *sniffer;
public:
  Router(std::string if_internal, std::string mac_internal);
  void start();
  bool handle(Tins::PDU&);
};


#endif
