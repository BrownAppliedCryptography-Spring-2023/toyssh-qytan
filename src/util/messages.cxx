#include <cassert>

#include "util/messages.hpp"
#include "util/util.hpp"
#include "util/constants.hpp"
#include "util/logger.hpp"

/**
 * serialize HMACTagged_Wrapper.
 */
std::vector<unsigned char> HMACTagged_Wrapper::serialize() {
  // Add message type.
//   data.push_back((char)MessageType::HMACTagged_Wrapper);

//   // Add fields.
//   put_string(chvec2str(this->payload), data);

//   std::string iv = byteblock_to_string(this->iv);
//   put_string(iv, data);

//   put_string(this->mac, data);
    return {};
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(const_buf &data) {
  // Check correct message type.
//   assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
//   n += get_string(&payload_string, data, n);
//   this->payload = str2chvec(payload_string);

//   std::string iv;
//   n += get_string(&iv, data, n);
//   this->iv = string_to_byteblock(iv);

//   n += get_string(&this->mac, data, n);
  return n;
}

Packet::buf Packet::serialize() {
    buf data;

    padding_length = 2 * 8 - ((sizeof(packet_length) + payload.size() + sizeof(padding_length)) % 8);

    packet_length = payload.size() + padding_length + sizeof(padding_length);

    put_integer_big(packet_length, data);
    put_integer_big(padding_length, data);

    data.insert(data.end(), payload.begin(), payload.end());
    data.resize(sizeof(packet_length) + packet_length);

    if (!mac.empty()) {
        data.insert(data.end(), mac.begin(), mac.end());
    }
    return data;
}

int Packet::deserialize(const_buf &data, bool mac) {
    this->packet_length = data.size();
    if (mac) {
        this->packet_length -= MAC_SIZE;
        buf mac_buf(data.begin() + packet_length, data.end());
        assert(mac_buf.size() == MAC_SIZE);
        this->mac = std::move(mac_buf);
    }

    return deserialize(data) + this->mac.size();
}

// without mac
int Packet::deserialize(const_buf &data) {
    size_t cnt = 0;
    get_integer_big(&this->padding_length, data, cnt);
    
    size_t payload_length = packet_length - padding_length - sizeof(padding_length);
    buf payload(data.begin() + cnt, data.begin() + cnt + payload_length);
    this->payload = std::move(payload);
    
    return packet_length;
}