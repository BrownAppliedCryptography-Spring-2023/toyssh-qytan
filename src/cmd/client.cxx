#include <sodium/core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "../../include/util/logger.hpp"
#include "pkg/ssh_client.hpp"

#define BUFSIZE 1024

int main(int argc, char **argv) {
    initLogger();
    if (argc != 5) {
        std::cerr << "usage: toy_ssh <user_name> <private_key_file> <address> <port>" << std::endl;
        return -1;
    }
    int port = std::stoi(argv[4]);
    SSHClient client(argv[1], argv[2], argv[3], port);
    client.run();
    return 0;
}