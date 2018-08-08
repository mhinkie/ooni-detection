#include "queue/detect_ooni/status_queue.h"
#include <boost/thread/locks.hpp>
#include <stdexcept>


std::string IntegerStatusQueue::get_printable_status(Tins::IPv4Address address) {
  int status = this->get_status(address);
  return "" + status;
}

std::unordered_map<Tins::IPv4Address, std::string> IntegerStatusQueue::get_all_printable_status() {
  std::unordered_map<Tins::IPv4Address, std::string> ret_map;
  std::unordered_map<Tins::IPv4Address, int> all_status = this->get_all_status();

  for_each(all_status.begin(), all_status.end(),
    [&ret_map](std::pair<const Tins::IPv4Address, int> &entry) {
      ret_map[entry.first] = entry.second + "";
    }
  );

}
