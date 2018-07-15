#include "det.h"

using namespace Tins;
using namespace libconfig;

Config config;

bool callback(const PDU &pdu) {
    const EthernetII &eth_pdu = pdu.rfind_pdu<EthernetII>();
    
    std::cout << eth_pdu.src_addr() << " -> "
         << eth_pdu.dst_addr() << std::endl;
    return true;
}

int main(int argc, char **argv) {
    //Sniffer("wlx2824ff1a05f9").sniff_loop(callback);
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

    std::string if_internal;
    std::string mac_internal;
    // Brauche zum starten den Config-Wert if_internal
    if(config.lookupValue("if_internal", if_internal) && config.lookupValue("mac_internal", mac_internal)) {
      // Pakete lesen
      SnifferConfiguration config;
      config.set_promisc_mode(false); // Ich bin router, also will ich nur pakete die an mich als def gw gesendet werden.
      config.set_immediate_mode(true); // Damit die packets nicht zwischengespeichert werden, sondern gleich zu mir kommen

      std::stringstream sStream;
      sStream << "ether dst " << mac_internal;
      config.set_filter(sStream.str()); // Nur pakete die meine interne mac als destination haben werden abgefangen

      std::cout << "Listening for incoming frames on interface " << if_internal << " - mac " << mac_internal << std::endl;

      Sniffer sniffer(if_internal, config);
      sniffer.sniff_loop(callback);
    } else {
      std::cerr << "Not al required configuration parameters supplied!" << std::endl;
    }

    return 0;
}
