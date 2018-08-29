#include "protocol/http.h"
#include <string>

const PDU::PDUType HTTP::pdu_flag = static_cast<PDU::PDUType>(PDU::USER_DEFINED_PDU + HTTP_PDU_FLAG);

void HTTP::parse() {
  char method_c[10];
  uint8_t space = (uint8_t)(' ');

  auto current = buffer.begin();
  // Find method and path
  int i=0;
  for(;current != buffer.end() && i < 10;current++) {
    if((*current) != space) {
      // Add to method
      method_c[i] = *current;
      i++;
    } else {
      // method finished
      break;
    }
  }
  // NULL termination
  method_c[9] = 0;

  std::string method_s(method_c);

  if(method_s == "GET") {
    this->_method = HTTP::GET;
  } else if(method_s == "POST") {
    this->_method = HTTP::POST;
  } else {
    throw Tins::malformed_packet();
  }

  // location
  char location_c[2];
  i = 0;
  for(;current != buffer.end() && i < 2;current++) {
    if((*current) != space) {
      location_c[i] = *current;
      i++;
    } else {
      break;
    }
  }
  location_c[1] = 0;
  _location = new std::string(location_c);
}
