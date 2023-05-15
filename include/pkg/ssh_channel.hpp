#pragma once
#include <cstdint>
#include <memory>
#include <boost/thread/barrier.hpp>

#include "util/ssh.hpp"

class SSHClient;
class Channel {
public:
    uint32_t receipt_id;
    uint32_t init_windows;
    uint32_t max_packet;
    int exit;
    void setup(uint32_t rec_id, uint32_t init_win, uint32_t max_pack);
    void cleanup();

private:
    std::shared_ptr<boost::barrier> barrier;

private:
    Channel();
    Channel(std::shared_ptr<boost::barrier> barrier) : barrier(barrier) {}
    friend class SSHClient;
};