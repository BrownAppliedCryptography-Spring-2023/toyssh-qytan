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

#define BUFSIZE 1024

int main(int argc, char **argv) {
    initLogger();

    SSHClient client("qiyetan", "localhost", 22);
    client.run();
    return 0;
}