#include "det.h"

using namespace Tins;
using namespace libconfig;

Config config;

Router::Router(std::string if_internal, std::string mac_internal, std::string if_external, std::string mac_external, std::string def_gw_mac)
  : if_internal(if_internal), mac_internal(mac_internal), if_external(if_external), mac_external(mac_external), def_gw_mac(def_gw_mac) {

  // Konfiguration für internal -> external
  SnifferConfiguration config;
  config.set_promisc_mode(false); // Ich bin router, also will ich nur pakete die an mich als def gw gesendet werden.
  config.set_immediate_mode(true); // Damit die packets nicht zwischengespeichert werden, sondern gleich zu mir kommen

  std::stringstream sStream;
  sStream << "ether dst " << this->mac_internal;
  config.set_filter(sStream.str()); // Nur pakete die meine interne mac als destination haben werden abgefangen

  sniffer = new Sniffer(this->if_internal, config);

  // Outgoing sender
  NetworkInterface outgoing_interface(if_external);
  this->outgoing_sender.default_interface(outgoing_interface);


}

void Router::start() {
  std::cout << "Listening for incoming frames on interface " << if_internal << " - mac " << mac_internal << std::endl;
  std::cout << "Routing via " << if_external << " - mac " << mac_external << " to " << def_gw_mac << std::endl;
  this->sniffer->sniff_loop(make_sniffer_handler(this, &Router::handleInternal));
  std::cout << "end of sniff loop";
}

bool Router::handleInternal(PDU &pdu) {
    EthernetII &eth_pdu = pdu.rfind_pdu<EthernetII>();

    // Vorgehensweise:
    // Ethernet PDU ändern...
    // - source_addr = mac von outgoing if
    // - dst_addr = mac von def gw
    // ... und dann senden

    std::cout << eth_pdu.src_addr() << " -> "
         << eth_pdu.dst_addr();

    // Paketweiterleitung:
    eth_pdu.src_addr(this->mac_external);
    eth_pdu.dst_addr(this->def_gw_mac);

    outgoing_sender.send(eth_pdu);

    std::cout << " == Sent packet to default gateway" << std::endl;

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

    std::string if_internal, mac_internal, if_external, mac_external, def_gw_mac;
    // Brauche zum starten den Config-Wert if_internal
    if(config.lookupValue("if_internal", if_internal)
      && config.lookupValue("mac_internal", mac_internal)
      && config.lookupValue("if_external", if_external)
      && config.lookupValue("mac_external", mac_external)
      && config.lookupValue("def_gw_mac", def_gw_mac)) {
      Router router(if_internal, mac_internal, if_external, mac_external, def_gw_mac);
      router.start();
    } else {
      std::cerr << "Not al required configuration parameters supplied!" << std::endl;
    }

    return 0;
}
