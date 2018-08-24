#include "queue/detect_ooni/facebook_messenger.h"

#include <iostream>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <sstream>
#include "util.h"

using namespace Tins;

std::unordered_map<std::string, FBName> dname_name = {
  {"b-api.facebook.com", FBName::b_api},
  {"b-graph.facebook.com", FBName::b_graph},
  {"edge-mqtt.facebook.com", FBName::edge},
  {"external.xx.fbcdn.net", FBName::external_cdn},
  {"scontent.xx.fbcdn.net", FBName::scontent_cdn},
  {"star.c10r.facebook.com", FBName::star}
};

FBMessengerQueue::FBMessengerQueue(int queue_num) : StatusQueue<FBStatus>(queue_num) {
}

FBMessengerQueue::~FBMessengerQueue() {
  TRACE("destroying fb messenger queue");
}

int FBMessengerQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // only packets going from facebook to the local network are detected
  // becaus of iptables rules (so only handle_ext_to_int is used)
  IP packet = parse_ip_packet(nfad);

  TCP *tcp_pdu = packet.find_pdu<TCP>();

  if(tcp_pdu != NULL) {
    // only check TCP
    return this->handle_ext_to_int(queue, nfmsg, nfad, packet, tcp_pdu);
  } else {
    UDP *udp_pdu = packet.find_pdu<UDP>();
    if(udp_pdu != NULL) {
      // This is a dns request going out
      return this->handle_int_to_ext(queue, nfmsg, nfad, packet, udp_pdu);
    } else {
      // everything else is accepted
      ACCEPT_PACKET(queue, nfad);
    }
  }
}

int FBMessengerQueue::handle_ext_to_int(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  IP &packet,
  TCP *tcp_pdu) {

  // Only allow SYNACK and FINACK packets
  // packets for data transmission are not allowed
  if(tcp_pdu->flags() == (TCP::SYN | TCP::ACK)) {
    TRACE("allowing SYNACK");
    ACCEPT_PACKET(queue, nfad);
  }
  if(tcp_pdu->flags() == (TCP::FIN | TCP::ACK)) {
    TRACE("allowing FINACK");
    ACCEPT_PACKET(queue, nfad);
  }

  TRACE("BLOCKING FACEBOOK PACKET");
  DROP_PACKET(queue, nfad);
}

int FBMessengerQueue::handle_int_to_ext(
  struct nfq_q_handle *queue,
  struct nfgenmsg *nfmsg,
  struct nfq_data *nfad,
  IP &packet,
  UDP *udp_pdu) {

  // OONI will lookup the following addresses (in an undefined order)
  // if all requests were received the sending host will be marked as a probable probe
  /*
  'b_api': "b-api.facebook.com",
  'b_graph': "b-graph.facebook.com",
  'edge': "edge-mqtt.facebook.com",
  'external_cdn': "external.xx.fbcdn.net",
  'scontent_cdn': "scontent.xx.fbcdn.net",
  'star': "star.c10r.facebook.com" */

  // Ceck if this is a dns packet
  RawPDU *inner_pdu = udp_pdu->find_pdu<RawPDU>();
  if(inner_pdu != NULL) {
    try {
      DNS dns_pdu = inner_pdu->to<DNS>();

      // Converting succeeded
      TRACE("got dns packet for inspection");
      // packet should be query
      if(dns_pdu.type() == DNS::QUERY) {
        std::vector<DNS::query> queries = dns_pdu.queries();
        if(queries.size() == 0) {
          TRACE("no queries found!");
        } else {
          if(queries.size() > 1) {
            TRACE("more than one query found - inspecting only the first");
          }

          DNS::query dns_query = queries[0];
          // lookup queried name to see if it is a facebook host
          try {
            FBName &facebook_server = dname_name.at(dns_query.dname());

            // Add to status for the sending host
            this->add_queried_name(facebook_server, packet.src_addr());
          } catch(std::out_of_range e) {
            TRACE("not a facebook host: " << dns_query.dname());
          }
        }
      } else {
        TRACE("packet is not a query!");
      }

    } catch(malformed_packet e) {
      // Not dns = just accept
    }
  }

  ACCEPT_PACKET(queue, nfad);
}

std::string format_status(const FBStatus &status) {
  std::ostringstream out;
  std::chrono::milliseconds current = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());

  if(status.second == PROBE_MARK) {
    out << "PROBE";
  } else {
    if(status.second + MAX_QUERY_WINDOW < current) {
      out << "Query time ran out (after " << status.first.size() << " queried names)";
    } else {
      std::chrono::milliseconds time_elapsed = current - status.second;
      out << status.first.size() << " host already queried " << time_elapsed.count() << "ms ago";
    }
  }

  return out.str();
}

/**
 * Returns a printable version of the status of the given IP.
 * @param  address the ip.
 * @return         a readable version of the status.
 */
std::string FBMessengerQueue::get_printable_status(Tins::IPv4Address address) {
  return format_status(get_status(address));
}

/**
 * Returns a printable status of all tracked IPs
 */
std::unordered_map<Tins::IPv4Address, std::string> FBMessengerQueue::get_all_printable_status() {
  std::unordered_map<Tins::IPv4Address, FBStatus> all_status = get_all_status();
  std::unordered_map<Tins::IPv4Address, std::string> printable_status;
  for(auto status_pair : all_status) {
    printable_status[status_pair.first] = format_status(status_pair.second);
  }
  return printable_status;
}

void FBMessengerQueue::add_queried_name(const FBName &fb_server, const Tins::IPv4Address &address) {
  // Get current time to check for time since the last query
  std::chrono::milliseconds current = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());

  // get info on sending host
  FBStatus status = get_status(address);

  if(status.second == PROBE_MARK) {
    TRACE("Host is already marked as probe");
  } else {
    TRACE("got status: " << address << ": (time: " << status.second.count() << ", queried_hosts: " << status.first.size() << ")");

    status.first.insert(fb_server);

    // check if query time ran out
    if((status.second + MAX_QUERY_WINDOW) < current) {
      TRACE("query time ran out for " << address << " (or new host)");
      // delete already queried hosts
      status.first.clear();
      status.first.insert(fb_server); // add this one server
      status.second = current; // add the query time
    } else {
      if(status.first.size() >= FB_SERVER_COUNT) {
        // all servers queries = mark as Probe
        TRACE("found probe: " << address);
        status.second = PROBE_MARK;
      } else {
        status.second = current;
      }
    }

    TRACE("updated status");

    set_status(address, status);
  }

}
