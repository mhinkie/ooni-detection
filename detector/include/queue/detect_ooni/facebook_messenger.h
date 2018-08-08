#ifndef FACEBOOK_MESSENGER_H
#define FACEBOOK_MESSENGER_H

#include "queue/detect_ooni/status_queue.h"
#include <unordered_map>
#include <unordered_set>
#include "util.h"

#define FB_SERVER_COUNT 6

/**
 * Names identifying the facebook hosts that will be resolved using dns
 */
enum class FBName {b_api, b_graph, edge, external_cdn, scontent_cdn, star};

// Hash für FBName
namespace std {
  template<> struct hash<FBName> {
      size_t operator()(const FBName &name) const {
          return (size_t)name;
      }
  };
}

/**
 * Map associating every facebook dns_name with the FBNames name. <br />
 * used for looking up if this server is part of oonis-test servers.
 */
extern std::unordered_map<std::string, FBName> dname_name;

/**
 * Maximum time allowed between facebook dns queries. After that, the set of
 * already queried dns names is discarded.
 */
const std::chrono::milliseconds MAX_QUERY_WINDOW {5000};

const std::chrono::milliseconds PROBE_MARK {-1};

/**
 * Queue implementation that blocks access to facebook messenger,
 * but circumvents OONI detection, meaning although access to facebook
 * messenger is blocked, OONI will think it is not blocked. <br />
 * This queue will keep status about hosts as a set of already queried
 * dns names.
 * <p>
 *  FBMessengerQueue treats all incoming and outgoing as packets going to or
 *  coming from facebook. To create iptables rules which match this requirement
 *  facebook_messenger.sh is used.
 * </p>
 * <p>
 *  Will only handle IPv4 for the moment.
 * </p>
 * Status format: <br />
 * pair: (names, time):<br />
 * names: a set of already visited facebook servers - if all are visited this host is marked as a probe <br />
 * time: the time of the last dns query to a facebook server - if the last query was more than a minute ago, the names is reset <br />
 * if the host is marked as a probe, time is set to -1
 * @see StatusQueue
 */
class FBMessengerQueue : public StatusQueue<std::pair<std::unordered_set<FBName>, std::chrono::milliseconds>> {
private:

  /**
   * Handles packets coming from the inside network and going to a facebook server.
   * <b>This function should only receive DNS-request going out.</b>
   * DNS requests are monitor for detection purposes (no blocking will be performed).
   * @param  queue  The nfq_q_handle (for setting the verdict)
   * @param  nfmsg  The nfgenmsg
   * @param  nfad   The nfq_data in case of additional required parsing
   * @param  packet The ip-packet parsed using libtins.
   * @param  tcp_pdu A pointer to the tcp pdu of the given packet for convenience.
   * @return        Should return the return value of nfq_set_verdict (using makros ACCEPT_PACKET, DROP_PACKET)
   */
  int handle_int_to_ext(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::UDP *udp_pdu);
  /**
   * Handles packets coming from a facebook server and being routed to the inside network
   * @param  queue  The nfq_q_handle (for setting the verdict)
   * @param  nfmsg  The nfgenmsg
   * @param  nfad   The nfq_data in case of additional required parsing
   * @param  packet The ip-packet parsed using libtins.
   * @param  tcp_pdu A pointer to the tcp pdu of the given packet for convenience.
   * @return        Should return the return value of nfq_set_verdict (using makros ACCEPT_PACKET, DROP_PACKET)
   */
  int handle_ext_to_int(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::TCP *tcp_pdu);

  /**
   * Adds a facebook server to the set of queried servers (and checks elapsed times).
   * @param fb_server The server to add.
   * @param address   the ip of the host querying the name.
   */
  void add_queried_name(const FBName &fb_server, const Tins::IPv4Address &address);
public:

  /**
   * Initializes the fb-messenger queue.
   * @param queue_num The number of this queue in iptables.
   * @throws std::runtime_error if not all facebook servers can be resolved.
   */
  FBMessengerQueue(int queue_num);
  virtual ~FBMessengerQueue();
  /**
   * Handles packets for facebook detection.<br />
   * OONI probes only check tcp-connection setup to see if facebook is reachable.
   * So the setup will be allowed to all servers, but all subsequent communication will be blocked.
   * @param  queue
   * @param  nfmsg
   * @param  nfad
   * @return
   */
  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);

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
