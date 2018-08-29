#ifndef TELEGRAM_H
#define TELEGRAM_H

#include "queue/detect_ooni/expiring_queue.h"

enum class TelegramDestination {v, eX, web};

// Hash for FBName
namespace std {
  template<> struct hash<TelegramDestination> {
      size_t operator()(const TelegramDestination &name) const {
          return (size_t)name;
      }
  };
}

class TelegramQueue : public ExpiringQueue<TelegramDestination> {
private:

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

public:


  TelegramQueue(int queue_num);
  virtual ~TelegramQueue();

  int handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);

};

#endif
