#ifndef HTTP_H
#define HTTP_H

#include <tins/tins.h>
#include <string>

#define HTTP_PDU_FLAG 2

using namespace Tins;

/*
 * HTTP (very limited functionality)
 */
class HTTP : public PDU {
public:
    static const PDU::PDUType pdu_flag;

    enum Method {
      GET,
      POST
    };

    HTTP(const uint8_t* data, uint32_t sz)
    : buffer(data, data + sz) {
      parse();
    }

    HTTP* clone() const {
      return new HTTP(*this);
    }

    ~HTTP() {
      delete _location;
    }

    uint32_t header_size() const {
      return buffer.size();
    }

    PDUType pdu_type() const {
      return pdu_flag;
    }

    HTTP::Method method() {
      return _method;
    }

    void write_serialization(uint8_t *data, uint32_t sz) {
      buffer.assign(data, data + sz);
    }

    const std::vector<uint8_t>& get_buffer() const {
      return buffer;
    }
private:
  std::vector<uint8_t> buffer;

  void parse();
  HTTP::Method _method;
  std::string *_location;
};

#endif
