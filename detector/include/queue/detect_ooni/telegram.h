#ifndef TELEGRAM_H
#define TELEGRAM_H

#include "queue/detect_ooni/expiring_queue.h"
#include "util.h"

enum class TelegramDestination {
  web, /* the dns query to web.telegram.org */
  dc1_80, dc2_80, dc3_80, dc4_80, dc5_80, /* all dcs as specified in the ooni-test - for port 80 */
  dc1_443, dc2_443, dc3_443, dc4_443, dc5_443 /* all dcs as specified in the ooni-test - for port 443 */
};

enum TelegramTLSStatus : uint8_t { Initializing = 0, RequestSent = 1 };

// Hash for TelegramDestination
namespace std {
  template<> struct hash<TelegramDestination> {
      size_t operator()(const TelegramDestination &name) const {
          return (size_t)name;
      }
  };
}

class TelegramQueue : public ExpiringQueue<TelegramDestination> {
private:

  std::unordered_set<Tins::IPv4Address> blocked_ips;

  int handle_incoming_dns(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::UDP *udp_pdu);

  int handle_incoming_tls(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::TCP *tcp_pdu);

  int handle_outgoing_http(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::TCP *tcp_pdu);

  int handle_outgoing_tls(
    struct nfq_q_handle *queue,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfad,
    Tins::IP &packet,
    Tins::TCP *tcp_pdu);

public:


  TelegramQueue(int queue_num);
  virtual ~TelegramQueue();

  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);

};

#endif
