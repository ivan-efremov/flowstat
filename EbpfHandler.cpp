#include <cstdint>
#include <string>
#include <iostream>
#include <cstdint>
#include "EbpfHandler.h"
#include "Filters.h"
#include "Utils.h"


extern PVectorFilters g_filters;


static std::string event2String(eBPFevent* e)
{
    switch(e->etype) {
    case eTCP_ACPT:
        return("ACCEPT");
        break;
    case eTCP_CONN:
        return("CONNECT");
        break;
    case eTCP_CONN_FAIL:
        return("CONNECT_FAILED");
        break;
    case eTCP_CLOSE:
        return("CLOSE");
        break;
    case eTCP_RETR:
        return("RETRANSMIT");
        break;
    case eUDP_SEND:
        return("SEND");
        break;
    case eUDP_RECV:
        return("RECV");
        break;
    }
    return std::to_string(e->etype);
}

void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize)
{
    eBPFevent       event;
    bool            isMatch = true;
    //struct sock *sk = (struct sock *) PT_REGS_RC(t_bpfctx);

    memcpy(&event, t_data, sizeof(eBPFevent));
    ebpf_preprocess_event(&event);

    for(auto &f : *g_filters) {
        if(!f(&event)) {
            isMatch = false;
            break;
        }
    }
    if(isMatch) {
        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);
        std::cout << "[" << event2String(&event) << "] "
                  << event.ifname << " "
                  << (int)event.proto << " "
                  << event.proc.task << " "
                  << "["
                  << ip2str(event.addr.v4.saddr)
                  << ":"
                  << event.sport
                  << " <-> "
                  << ip2str(event.addr.v4.daddr)
                  << ":"
                  << event.dport
                  << "] "
                  << (unsigned int)event.event_time.tv_sec
                  << "."
                  << (unsigned int)event.event_time.tv_usec
                  << " "
                  << double(event.latency_usec / (double)1000.0)
                  << " "
                  << ((float)(tp.tv_nsec-(event.ktime % 1000000000)) / (float)1000)
                  << std::endl;
    }
    ebpf_free_event(&event);
}

