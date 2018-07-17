#include "router.h"


#include <thread>
#include <sstream>
#include <iostream>

using namespace Tins;

Router::Router(std::string if_internal,
  std::string mac_internal,
  std::string if_external,
  std::string mac_external,
  std::string def_gw_mac,
  std::string dst_network,
  std::string host_mac,
  Detector *detector)
  : if_internal(if_internal), mac_internal(mac_internal), if_external(if_external), mac_external(mac_external), def_gw_mac(def_gw_mac), host_mac(host_mac), detector(detector) {

  // config for internal -> external
  SnifferConfiguration config_internal;
  config_internal.set_promisc_mode(false); // only use pakets addressed to me
  config_internal.set_immediate_mode(true); // disable buffering of pakets

  std::stringstream sStream;
  sStream << "ether dst " << this->mac_internal;
  config_internal.set_filter(sStream.str()); // only get unicast pakets addressed to me
  std::cout << "Internal filter: " << sStream.str() << std::endl;

  this->internal_sniffer = new Sniffer(this->if_internal, config_internal);

  // Outgoing sender
  NetworkInterface outgoing_interface(if_external);
  this->outgoing_sender.default_interface(outgoing_interface);


  // config for external -> internal
  SnifferConfiguration config_external;
  config_external.set_promisc_mode(false);
  config_external.set_immediate_mode(true);

  sStream.str(std::string(""));
  sStream << "ether dst " << this->mac_external;
  sStream << " and dst net " << dst_network; // to filter out ssh connections
  config_external.set_filter(sStream.str());
  std::cout << "External filter: " << sStream.str() << std::endl;

  this->external_sniffer = new Sniffer(this->if_external, config_external);

  // Incoming sender (ext_to_int) is already intialized
  NetworkInterface incoming_interface(if_internal);
  this->incoming_sender.default_interface(incoming_interface);
}

/** start external to internal routing */
void start_ext_to_int(Sniffer *sniffer, Router *router) {
  std::cout << "Starting ext_to_int" << std::endl;
  sniffer->sniff_loop(make_sniffer_handler(router, &Router::handleExternal));
}

/** starts internal to external routing */
void start_int_to_ext(Sniffer *sniffer, Router *router) {
  std::cout << "Starting int_to_ext" << std::endl;
  sniffer->sniff_loop(make_sniffer_handler(router, &Router::handleInternal));
}

void Router::start() {
  std::cout << "Listening for incoming frames on interface " << if_internal << " - mac " << mac_internal << std::endl;
  std::cout << "Routing via " << if_external << " - mac " << mac_external << " to " << def_gw_mac << std::endl;
  // ext_to_int
  std::thread ext_to_int_thread(start_ext_to_int, this->external_sniffer, this);
  // int_to_ext
  start_int_to_ext(this->internal_sniffer, this);
}

/** Debug output or pdus (prints types as integers) */
void outputPDU(PDU *pdu) {
  std::cerr << "PDU: (";
  while(pdu != NULL) {
    std::cerr << pdu->pdu_type() << ", ";
    pdu = pdu->inner_pdu();
  }
  std::cerr << ")";
}

bool Router::handleExternal(PDU &pdu) {
  EthernetII &eth_pdu = pdu.rfind_pdu<EthernetII>();

  // Routing is done manually, because handling of IP-Pakets causes problems with MTU size

  std::cout << "ext_to_int: " << eth_pdu.src_addr() << " -> "
       << eth_pdu.dst_addr();

  // Routing:
  // Source = own mac
  // Destination = left empty
  eth_pdu.src_addr(this->mac_internal);
  eth_pdu.dst_addr(this->host_mac);

  try {
    // Only send ip pdu
    this->incoming_sender.send(eth_pdu);
    std::cout << " == Sent packet to " << (eth_pdu).dst_addr() << std::endl;
  } catch(socket_write_error err) {
    std::cerr << " !!!! Write error on ext_to_int '" << err.what() << "' size: " << eth_pdu.size() << " - destination " << (eth_pdu).dst_addr() << " ";
    outputPDU(&eth_pdu);
    std::cerr << std::endl;
  }

  return true;
}

bool Router::handleInternal(PDU &pdu) {
    EthernetII &eth_pdu = pdu.rfind_pdu<EthernetII>();

    // change ethernet pdu:
    // - source_addr = mac of outgoing if
    // - dst_addr = mac of def gw

    std::cout << eth_pdu.src_addr() << " -> "
         << eth_pdu.dst_addr();

    // paket forwarding:
    eth_pdu.src_addr(this->mac_external);
    eth_pdu.dst_addr(this->def_gw_mac);

    if(this->detector == NULL || this->detector->process(eth_pdu)) {
      try {
        outgoing_sender.send(eth_pdu);
        std::cout << " == Sent packet to default gateway (l2 size: " << eth_pdu.size() << ")" << std::endl;
      } catch(socket_write_error err) {
        std::cerr << " !!!! Write error on int_to_ext '" << err.what() << "' size: " << eth_pdu.size() << " ";
        outputPDU(&eth_pdu);
        std::cerr << std::endl;
      }
    } else {
      std::cerr << "Detector rejected packet" << std::endl;
    }

    return true;
}
