#include <arpa/inet.h>
#include "Utils.h"

uint64_t str2ip(const std::string& str)
{
    struct sockaddr_in sa;
    if(0 == inet_pton(AF_INET, str.c_str(), &sa.sin_addr)) {
        return 0UL;
    }
    return uint64_t(ntohl(sa.sin_addr.s_addr));
}

std::string ip2str(uint32_t addr)
{
    std::string str;
    str.reserve(16);
    str += std::to_string(addr >> 24 & 0xFF) + '.';
    str += std::to_string(addr >> 16 & 0xFF) + '.';
    str += std::to_string(addr >> 8  & 0xFF) + '.';
    str += std::to_string(addr & 0xFF);
    return str;
}
