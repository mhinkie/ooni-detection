#ifndef HTTPS_BACKEND
#define HTTPS_BACKEND

#include "queue/detect_ooni/expiring_queue.h"

#include <unordered_set>
#include <memory>

enum class BackendStep {
  dns_bouncer, /* bouncer.ooni.io is queried */
  tcp_bouncer, /* bouncer.ooni.io is contacted */
  dns_collector, /* *.collector.ooni.io is queried */
  tcp_collector /* *.collector.ooni.io is contacted */
};

// Hash for BackendStep
namespace std {
  template<> struct hash<BackendStep> {
      size_t operator()(const BackendStep &name) const {
          return (size_t)name;
      }
  };
}

class HTTPSBackendQueue : public ExpiringQueue<BackendStep> {
private:
  /* there are multiple collectors - this set saved every
  address returned by dns responses */
  std::unordered_set<Tins::IPv4Address> collector_addresses;
  std::unique_ptr<Tins::IPv4Address> bouncer_address;

  /**
   * Receives incoming dns pdus. <br />
   * Reads the dns-answers to <br />
   * 1: determine if bouncer.ooni.io or *.collector.ooni.io is queried
   * 2: save the returned address of bouncer.ooni.io and *.collector.ooni.io
   * @param  queue   the nfqueue handle
   * @param  nfmsg
   * @param  nfad
   * @param  packet  The tins ip packet
   * @param  udp_pdu A pointer to the udp pdu of the packet
   * @return         nfqueue verdict
   */
  int handle_incoming_dns(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, Tins::IP &packet, Tins::UDP *udp_pdu);

  /**
   * Receives outgoing tcp pdus. <br />
   * Checks wheter the destination of these packets is the saved ip of
   * bouncer.ooni.io or collector.ooni.io
   * @param  queue   the nfqueue handle
   * @param  nfmsg
   * @param  nfad
   * @param  packet  The tins ip packet
   * @param  tcp_pdu A pointer to the tcp pdu of the packet
   * @return         nfqueue verdict
   */
  int handle_outgoing_tcp(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, Tins::IP &packet, Tins::TCP *tcp_pdu);
public:
  /**
   * Creates a backend-queue. This queue tries to detect OONI-probes using the
   * messages the HTTPS-preferred-backend sends.<br />
   * This queue will not detect OONI if any other backend is selected.<br />
   * The queue tries to detect communication to bouncer.ooni.io and collector.ooni.io within
   * 2 seconds.
   * @param queue_num The nfqueue queue-number.
   */
  HTTPSBackendQueue(int queue_num);
  virtual ~HTTPSBackendQueue();

  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);

};



#endif
