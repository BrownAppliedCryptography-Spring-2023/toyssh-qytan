#include <sodium/core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "../../include/util/logger.hpp"
#include "pkg/ssh_client.hpp"

extern "C" {
#include "global.h"
}

#define BUFSIZE 1024

int main(int argc, char **argv) {
    global_init();
    initLogger();
    // if (sodium_init() != 0) {
    //     std::cerr << "sodium init failed" << std::endl;
    //     return -1;
    // };

    SSHClient client("localhost", 22);
    client.run();
    return 0;
}