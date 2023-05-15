#include <iostream>
#include <cryptopp/cryptlib.h>
#include "pkg/ssh_channel.hpp"

void Channel::setup(uint32_t rec_id, uint32_t init_win, uint32_t max_pack) {
    receipt_id = rec_id;
    init_windows = init_win;
    max_packet = max_pack;
    this->barrier->count_down_and_wait();
}

void Channel::cleanup() {
    // nothing currently
}