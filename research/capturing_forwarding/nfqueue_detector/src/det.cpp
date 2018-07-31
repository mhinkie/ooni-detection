#include "det.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <netinet/in.h>
#include <linux/netfilter.h>	

/**
 * A pointer to the wrapper should be passed to the callback funtion
 */
int global_callback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *wrapper) {
  if(wrapper == NULL) {
    // if for some reason the wrapper is not supplied, the packet will be accepted
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfad);
    u_int32_t id = ntohl(ph->packet_id);
    return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
  } else {
    return ((NFQueue*)wrapper)->handle_pkt(queue, nfmsg, nfad);
  }
}



NFQueue::NFQueue(int queue_number) {
  std::cout << "Setting up nfqueue" << std::endl;

  this->handle = nfq_open();
  if(this->handle == NULL) {
    throw std::runtime_error("error opening nfqueue handle");
  }

  std::cout << "Trying to start nfqueue detector for queue " << queue_number << std::endl;
  /* the NFQueue Object will be passed to the callback funtion so the general
  callback function (global_callback) can call the callback function associated with the queue */
  this->queue = nfq_create_queue(this->handle, queue_number, &global_callback, this);
}

NFQueue::~NFQueue() {
  std::cout << "Deleting nfqueue" << std::endl;
  nfq_close(this->handle);
}

int NFQueue::handle_pkt(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
  // accepting all
  std::cout << "accepting" << std::endl;

  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfad);
  u_int32_t id = ntohl(ph->packet_id);
  return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}



int main(int argc, char **argv) {
  if(argc < 2) {
    std::cerr << "Please supply a queue number" << std::endl;
    return 1;
  }

  try {
    int queue_number = std::stoi(argv[1]);
    NFQueue q(queue_number);
  } catch(std::logic_error e) {
    std::cerr << "Invalid value for queue number: " << argv[1] << std::endl;
    return 1;
  }

  return 0;
}
