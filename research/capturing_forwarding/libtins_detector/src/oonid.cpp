/**
 * OONI Detector
 * starts a router using libtins which decides for each packet if it should be forwarded or not
 */

#include "router.h"
#include "det_dns.h"

#include <libconfig.h++>
#include <iostream>

using namespace Tins;
using namespace libconfig;

Config config;

int main(int argc, char **argv) {
    if(argc < 2) {
      std::cerr << "No configuration file given!" << std::endl;
      return EXIT_FAILURE;
    }
    try {
      config.readFile(argv[1]);
    } catch(const FileIOException &fioex) {
      std::cerr << "Cannot read configuration file" << std::endl;
      return EXIT_FAILURE;
    }
    catch(const ParseException &pex) {
      std::cerr << "Error parsing configuration file " << pex.getFile() << ":" << pex.getLine()
                << " - " << pex.getError() << std::endl;
      return EXIT_FAILURE;
    }

    std::string if_internal, mac_internal, if_external, mac_external, def_gw_mac, dst_network, host_mac;
    // check for configuration values
    if(config.lookupValue("if_internal", if_internal)
      && config.lookupValue("mac_internal", mac_internal)
      && config.lookupValue("if_external", if_external)
      && config.lookupValue("mac_external", mac_external)
      && config.lookupValue("def_gw_mac", def_gw_mac)
      && config.lookupValue("dst_network", dst_network)
      && config.lookupValue("host_mac", host_mac)) {

      // detector
      std::unique_ptr<Detector> det(new DNSDetector);

      Router router(if_internal, mac_internal, if_external, mac_external, def_gw_mac, dst_network, host_mac, det.get());
      router.start();
    } else {
      std::cerr << "Not al required configuration parameters supplied!" << std::endl;
    }

    return 0;
}
