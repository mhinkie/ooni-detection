#include "queue/detect_ooni/status_queue.h"
#include <boost/thread/locks.hpp>
#include <stdexcept>

// shared lock for reading
#define READLOCK() boost::shared_lock<boost::shared_mutex> lock(this->mutex)
// unique lock for writing
#define WRITELOCK() boost::unique_lock<boost::shared_mutex> lock(this->mutex)

int StatusQueue::get_status(Tins::IPv4Address address) const {
  READLOCK();
  try {
    return this->ip_status.at(address);
  } catch(std::out_of_range e) {
    return STATUS_NO_PROBE;
  }
}

std::unordered_map<Tins::IPv4Address, int> StatusQueue::get_all_status() const {
  READLOCK();
  return this->ip_status;
}

void StatusQueue::set_status(Tins::IPv4Address ip, int status) {
  WRITELOCK();
  this->ip_status[ip] = status;
}

void StatusQueue::change_status(Tins::IPv4Address ip, int delta_status) {
  WRITELOCK();
  this->ip_status[ip] = this->ip_status[ip] + delta_status;
}
