#ifndef EXPIRING_QUEUE_H
#define EXPIRING_QUEUE_H

#include "queue/detect_ooni/status_queue.h"
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <string>

const std::chrono::milliseconds IS_PROBE {-1};

/**
 * The status entry saved in the expiring queue
 */
template<typename T>
using ProbeStatus = std::pair<std::unordered_set<T>, std::chrono::milliseconds>;





template<typename T>
class ExpiringQueue : public StatusQueue<ProbeStatus<T>> {
private:
  int num_destinations;
  std::chrono::milliseconds expiry_time;

  std::string format_status(const ProbeStatus<T> &status) {
    std::ostringstream out;
    std::chrono::milliseconds current = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());

    if(status.second == IS_PROBE) {
      out << "PROBE";
    } else {
      if(status.second + expiry_time < current) {
        out << "Query time ran out (after " << status.first.size() << " queried names)";
      } else {
        std::chrono::milliseconds time_elapsed = current - status.second;
        out << status.first.size() << " destinations already queried " << time_elapsed.count() << "ms ago";
      }
    }

    return out.str();
  }
protected:
  /**
  * Adds a destination to the list of queried destinations for the host.
  * @param fb_server The destination to add.
  * @param address   the ip of the host querying the name.
  */
  void add_queried_destination(const T &destination, const Tins::IPv4Address &address) {
    // Get current time to check for time since the last query
    std::chrono::milliseconds current = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());

    // get info on sending host
    ProbeStatus<T> status = this->get_status(address);

    if(status.second == IS_PROBE) {
      TRACE("Host is already marked as probe");
    } else {
      TRACE("got status: " << address << ": (time: " << status.second.count() << ", queried destinations: " << status.first.size() << ")");

      status.first.insert(destination);

      // check if query time ran out
      if((status.second + expiry_time) < current) {
        TRACE("query time ran out for " << address << " (or new host)");
        // delete already queried hosts
        status.first.clear();
        status.first.insert(destination); // add this one server
        status.second = current; // add the query time
      } else {
        if(status.first.size() >= num_destinations) {
          // all servers queries = mark as Probe
          TRACE("found probe: " << address);
          status.second = IS_PROBE;
        } else {
          status.second = current;
        }
      }

      TRACE("updated status");

      this->set_status(address, status);
    }
  }

  /**
  * Returns whethter or not this host is marked as a probe.
  * @param  address The host to query
  * @return         true if host is a probe, false otherwise
  */
  bool is_probe(const Tins::IPv4Address &address) {
    ProbeStatus<T> status = this->get_status(address);
    return status.second == IS_PROBE;
  }
public:
  /**
   * Initializes the expiring queue.
   * @param queue_num The number of this queue in iptables.
   * @param num_destinations After num_destinations destinations are found (added to the set) hosts are marked as probes.
   * @param expiry_time If expiry time is reached, the host is removed from the set of potential probes.
   * @throws std::runtime_error if initialization fails
   */
  ExpiringQueue(int queue_num, int num_destinations, std::chrono::milliseconds expiry_time)
  : StatusQueue<ProbeStatus<T>>(queue_num)
  , num_destinations(num_destinations)
  , expiry_time(expiry_time) {

  }
  virtual ~ExpiringQueue() {
    TRACE("destroying expiring queue");
  }

  /**
   * Handles packets for detection.<br />
   * OONI probes only check tcp-connection setup to see if facebook is reachable.
   * So the setup will be allowed to all servers, but all subsequent communication will be blocked.
   * @param  queue
   * @param  nfmsg
   * @param  nfad
   * @return
   */
  virtual int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) = 0;

  /**
   * Returns a printable version of the status of the given IP.
   * @param  address the ip.
   * @return         a readable version of the status.
   */
  virtual std::string get_printable_status(Tins::IPv4Address address) {
    return format_status(this->get_status(address));
  }

  /**
   * Returns a printable status of all tracked IPs
   */
  virtual std::unordered_map<Tins::IPv4Address, std::string> get_all_printable_status() {
    std::unordered_map<Tins::IPv4Address, ProbeStatus<T>> all_status = this->get_all_status();
    std::unordered_map<Tins::IPv4Address, std::string> printable_status;
    for(auto status_pair : all_status) {
      printable_status[status_pair.first] = format_status(status_pair.second);
    }
    return printable_status;
  }
};

#endif
