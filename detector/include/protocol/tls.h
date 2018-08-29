#ifndef TLS_H
#define TLS_H

#include <tins/tins.h>

#define TLS_PDU_FLAG 1

using namespace Tins;

/*
 * TLS PDU (limited functionality)
 */
class TLS : public PDU {
private:
  std::vector<uint8_t> buffer;
  uint8_t _content_type;
public:
    static const PDU::PDUType pdu_flag;

    enum ContentType {
      CHANGE_CHIPHER_SPEC = 20,
      ALERT = 21,
      HANDSHAKE = 22,
      APPLICATION_DATA = 23
    };

    TLS(const uint8_t* data, uint32_t sz)
    : buffer(data, data + sz) {
      _content_type = buffer[0];
    }

    TLS* clone() const {
        return new TLS(*this);
    }

    uint32_t header_size() const {
        return buffer.size();
    }

    PDUType pdu_type() const {
        return pdu_flag;
    }

    TLS::ContentType content_type() {
      return static_cast<TLS::ContentType>(_content_type);
    }

    void write_serialization(uint8_t *data, uint32_t sz) {
        buffer.assign(data, data + sz);
    }

    const std::vector<uint8_t>& get_buffer() const {
        return buffer;
    }
};

const PDU::PDUType TLS::pdu_flag = static_cast<PDU::PDUType>(PDU::USER_DEFINED_PDU + TLS_PDU_FLAG);

#endif
