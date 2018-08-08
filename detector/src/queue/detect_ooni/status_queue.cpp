#include "queue/detect_ooni/status_queue.h"
#include <boost/thread/locks.hpp>
#include <stdexcept>

// shared lock for reading
#define READLOCK() boost::shared_lock<boost::shared_mutex> lock(this->mutex)
// unique lock for writing
#define WRITELOCK() boost::unique_lock<boost::shared_mutex> lock(this->mutex)

template <typename T>
T StatusQueue<T>::get_status(Tins::IPv4Address address) const {
  READLOCK();
  try {
    return this->ip_status.at(address);
  } catch(std::out_of_range e) {
    return STATUS_NO_PROBE;
  }
}

template <typename T>
std::unordered_map<Tins::IPv4Address, T> StatusQueue<T>::get_all_status() const {
  READLOCK();
  return this->ip_status;
}

template <typename T>
void StatusQueue<T>::set_status(Tins::IPv4Address ip, T status) {
  WRITELOCK();
  this->ip_status[ip] = status;
}


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
