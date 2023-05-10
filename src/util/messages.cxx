#include <cassert>

#include "util/messages.hpp"
#include "util/util.hpp"
#include "util/logger.hpp"
#include "crypto/algorithms.hpp"

extern "C" {
#include "randombytes.h"
}

namespace {
    src::severity_logger<logging::trivial::severity_level> lg;
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