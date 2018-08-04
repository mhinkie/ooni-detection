#ifndef STATUS_QUEUE_H
#define STATUS_QUEUE_H

#include <unordered_map>
#include <tins/tins.h>
#include "det.h"
#include <climits>
#include <boost/thread/shared_mutex.hpp>

/** Indicates, that a host is not a probe or not examined */
#define STATUS_NO_PROBE INT_MIN
/** Indicates, that a host is probably an ooni-probe */
#define STATUS_PROBE 1

/**
 * Queue implementation, that is able to keep track of per-ip status information.
 * Depending on inspected packets, ips can be marked as possible ooni-probes. <br />
 * StatusQueue provides get_status(Tins::IPv4Address), which returns the status
 * for a ip-address and get_all_status(), which returns the status for all <e>checked</e>
 * addresses. A address is only checked, if the queue found it necesseary to mark this
 * ip with a specific status (meaning not all ips that are communicating are present in the queue).<br />
 * <p>
 *  Status are starting from INT_MIN (not examined, or no information indicating an ooni-probe found) (#STATUS_NO_PROBE),
 *  to 1 (#STATUS_PROBE) (indicating that is host is probably an ooni-probe). All positive values (> #STATUS_PROBE) can
 *  be used to encode additional information (like the probable version of the probe, or if the probe is testing at this moment...).
 * </p>
 * Implementing queues might not use the status-information for blocking or allowing packets at all, and
 * just keep it for documentation purposes.
 */
class StatusQueue : public NFQueue {
private:
  mutable boost::shared_mutex mutex;
  /** status for hosts as reported to "outside". every status queue might keep an internal map aswell */
  std::unordered_map<Tins::IPv4Address, int> ip_status;
protected:
  /**
   * Sets the status for this ip to a new value.
   * @param Tins::IPv4Address The ip to modify
   * @param status            The new status.
   */
  void set_status(Tins::IPv4Address ip, int status);
  /**
   * relatively changes the status for an ip
   * @param Tins::IPv4Address The ip to modify
   * @param delta_status      The change of status (+ = status is increased = more likely, - = status is decreased = less likely)
   */
  void change_status(Tins::IPv4Address ip, int delta_status);
public:
  /**
   * Initializes the status queue. Creates map containing status on hosts.
   * @see NFQueue::NFQueue()
   * @param queue_num [description]
   */
  StatusQueue(int queue_num) : NFQueue(queue_num) { }
  virtual ~StatusQueue() { std::cout << "destroying status queue" << std::endl; }
  virtual int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) = 0;

  /**
   * Returns the status for an ip-address. If no status is saved for this address, #STATUS_NO_PROBE is returned.
   * @param  address The address to return a status for.
   * @return         The status information.
   */
  int get_status(Tins::IPv4Address address) const;

  /**
   * Returns a copy of the internal status information for all examined hosts.
   */
  std::unordered_map<Tins::IPv4Address, int> get_all_status() const;
};

#endif
