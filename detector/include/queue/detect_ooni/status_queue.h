#ifndef STATUS_QUEUE_H
#define STATUS_QUEUE_H

#include <unordered_map>
#include <tins/tins.h>
#include "det.h"
#include <climits>
#include <boost/thread/shared_mutex.hpp>
#include <string>


// shared lock for reading
#define READLOCK() boost::shared_lock<boost::shared_mutex> lock(this->mutex)
// unique lock for writing
#define WRITELOCK() boost::unique_lock<boost::shared_mutex> lock(this->mutex)

/** NFQueue able to print debug output */
class PrintableQueue : public NFQueue {
public:
  PrintableQueue(int queue_num) : NFQueue(queue_num) { }
  virtual ~PrintableQueue() { DEBUG("destroying printable queue"); }
  /**
   * Returns a printable version of the status of the given IP.
   * @param  address the ip.
   * @return         a readable version of the status.
   */
  virtual std::string get_printable_status(Tins::IPv4Address address) = 0;

  /**
   * Returns a printable status of all tracked IPs
   */
  virtual std::unordered_map<Tins::IPv4Address, std::string> get_all_printable_status() = 0;
};

/**
 * Queue implementation, that is able to keep track of per-ip status information.
 * Depending on inspected packets, ips can be marked as possible ooni-probes. <br />
 * StatusQueue provides get_status(Tins::IPv4Address), which returns the status
 * for a ip-address and get_all_status(), which returns the status for all <e>checked</e>
 * addresses. A address is only checked, if the queue found it necesseary to mark this
 * ip with a specific status (meaning not all ips that are communicating are present in the queue).<br />
 * <p>
 *  Status can be any object (is implementation dependent)
 * </p>
 * Implementing queues might not use the status-information for blocking or allowing packets at all, and
 * just keep it for documentation purposes.
 */
template <typename T>
class StatusQueue : public PrintableQueue {
private:
  mutable boost::shared_mutex mutex;
  /** status for hosts as reported to "outside". every status queue might keep an internal map aswell */
  std::unordered_map<Tins::IPv4Address, T> ip_status;
protected:
  /**
   * Sets the status for this ip to a new value.
   * @param Tins::IPv4Address The ip to modify
   * @param status            The new status.
   */
  void set_status(Tins::IPv4Address ip, T status) {
    WRITELOCK();
    this->ip_status[ip] = status;
  }
public:
  /**
   * Initializes the status queue. Creates map containing status on hosts.
   * @see NFQueue::NFQueue()
   * @param queue_num [description]
   */
  StatusQueue(int queue_num) : PrintableQueue(queue_num) { }
  virtual ~StatusQueue() { DEBUG("destroying status queue"); }
  virtual int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) = 0;

  /**
   * Returns the status for an ip-address. (empty status if not already in set).
   * @param  address The address to return a status for.
   * @return         The status information.
   */
  T get_status(Tins::IPv4Address address) {
    READLOCK();
    return ip_status[address];
  }

  /**
   * Returns a copy of the internal status information for all examined hosts.
   */
  std::unordered_map<Tins::IPv4Address, T> get_all_status() const {
    READLOCK();
    return this->ip_status;
  }
};



class IntegerStatusQueue : public StatusQueue<int> {
public:
  /**
   * Initializes the status queue. Creates map containing status on hosts.
   * @see NFQueue::NFQueue()
   * @param queue_num [description]
   */
  IntegerStatusQueue(int queue_num) : StatusQueue<int>(queue_num) { }
  virtual ~IntegerStatusQueue() { DEBUG("destroying int-status queue"); }
  /**
   * Returns a printable version of the status of the given IP.
   * @param  address the ip.
   * @return         a readable version of the status.
   */
  virtual std::string get_printable_status(Tins::IPv4Address address);

  /**
   * Returns a printable status of all tracked IPs
   */
  virtual std::unordered_map<Tins::IPv4Address, std::string> get_all_printable_status();
};

#endif
