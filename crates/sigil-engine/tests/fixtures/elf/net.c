/* PR-4b-2a: a relocatable object that calls socket and connect (issue #46's case). Built by
 * build.sh; the tests read the committed net.o. */
#include <netinet/in.h>
#include <sys/socket.h>

int sigil_connect_loopback(unsigned short port) {
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = __builtin_bswap16(port);
    a.sin_addr.s_addr = __builtin_bswap32(0x7f000001);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    return connect(fd, (struct sockaddr *)&a, sizeof a);
}
