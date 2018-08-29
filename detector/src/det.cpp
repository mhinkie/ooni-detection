#include "det.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <thread>
#include <chrono>

// Queues
#include "queue/detect_ooni/facebook_messenger.h"
#include "queue/detect_ooni/whatsapp.h"
#include "queue/detect_ooni/telegram.h"
#include "queue/accept_all.h"

#define DEFAULT_POLICY NF_ACCEPT
#define DEBUG_OUTPUT_INTERVAL_S 10

/**
 * netfilter queue callback function. Function is called after a packet is processed
 * by netfilter_queue
 * (\link https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html#ga79f250ddd7568c2aefbd163b03e4e28b create queue \endlink). <br />
 * As additional data a pointer to the nfqueue wrapper is supplied. The callback function
 * should call the wrappers own callback function (or accept the packet if no
 * wrapper is supplied).
 * @param  queue   pointer to netfilter queue-handle
 * @param  nfmsg
 * @param  nfad
 * @param  wrapper The supplied wrapper object (NFQueue)
 * @return
 */
int global_callback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *wrapper) {
  if(wrapper == NULL) {
    // if for some reason the wrapper is not supplied, default policy will be used
    // i don't know if this can ever happen
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfad);
    u_int32_t id = ntohl(ph->packet_id);

    DEBUG("No queue object supplied - applying default policy");

    return nfq_set_verdict(queue, id, DEFAULT_POLICY, 0, NULL);
  } else {
    return ((NFQueue*)wrapper)->handle_pkt(queue, nfmsg, nfad);
  }
}



NFQueue::NFQueue(int queue_number) {
  DEBUG("Setting up nfqueue");

  this->handle = nfq_open();
  if(this->handle == NULL) {
    throw std::runtime_error("error opening nfqueue handle");
  }

  DEBUG("Trying to start nfqueue detector for queue " << queue_number);
  /* the NFQueue Object will be passed to the callback funtion so the general
  callback function (global_callback) can call the callback function associated with the queue */
  this->queue = nfq_create_queue(this->handle, queue_number, &global_callback, this);
  if(this->queue == NULL) {
    throw std::runtime_error("error creating queue");
  }
  DEBUG("Created queue " << queue_number);

  // The whole packets should be copied to user space
	if(nfq_set_mode(this->queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
    throw std::runtime_error("error setting packet copy mode");
  }


}

NFQueue::~NFQueue() {
  DEBUG("Deleting nfqueue");

  nfq_destroy_queue(this->queue);

  nfq_close(this->handle);
}


void NFQueue::start() {
  char buffer[4096] __attribute__ ((aligned));

  // File descriptor for nfqueue handle
  int fd = nfq_fd(this->handle);

  // received packet size
  int rsize = -1;
  // receive loop
  while ((rsize = recv(fd, buffer, sizeof(buffer), 0)) && rsize >= 0) {
    // packet will be handled by netfilter_queue (and given to callback function)
		nfq_handle_packet(this->handle, buffer, rsize);
  }

  DEBUG("receive loop finished");
}

/**
 * Returns the queue for the specific test name
 * @param  test_name Test name
 * @return           the queue which schould be started
 */
PrintableQueue *get_queue(std::string test_name, int queue_number) {
  if(test_name == std::string("facebook_messenger")) {
    return new FBMessengerQueue(queue_number);
  }
  if(test_name == std::string("whatsapp")) {
    return new WhatsappQueue(queue_number);
  }
  if(test_name == std::string("telegram")) {
    return new TelegramQueue(queue_number);
  }
  throw std::runtime_error("no appropriate queue found for test-name: " + test_name);
}

void debug_loop(PrintableQueue *queue) {
  std::chrono::seconds sleep_duration(DEBUG_OUTPUT_INTERVAL_S);
  while(true) {
    std::this_thread::sleep_for(sleep_duration);
    DEBUG("Current status:");
    for(auto entry : queue->get_all_printable_status()) {
      DEBUG(entry.first << ": " << entry.second);
    }
    DEBUG("");
  }
}

int main(int argc, char **argv) {
  if(argc < 2) {
    std::cerr << "Please supply a queue number and a optional test name" << std::endl;
    return 1;
  }

  try {
    int queue_number = std::stoi(argv[1]);

    if(argc == 3) {
      // Test name supplied - start this test
      std::string test_name(argv[2]);
      PrintableQueue *q = get_queue(test_name, queue_number);

      #ifdef ISDEBUG
            std::thread d_loop(debug_loop, q);
      #endif

      // Start processing
      q->start();


      delete q;
    } else {
      // No test name supplied - start allow_all queue
      AcceptAllQueue q(queue_number);

      q.start();
    }


  } catch(std::logic_error e) {
    std::cerr << "Invalid value for queue number: " << argv[1] << std::endl;
    return 1;
  } catch(std::runtime_error e) {
    std::cerr << e.what() << std::endl;
  }

  return 0;
}
