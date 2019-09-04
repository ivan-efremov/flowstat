#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <cassert>
#include <bcc/BPF.h>
#include "ebpf_flow.h"

#define SOURCE_FILE_LINE    (std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": ")


static int      s_isRun = true;
static void    *s_ebpf = NULL;
static short    s_flags = 0;

static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);


static void terminate(int sig)
{
    s_isRun = false;
    std::cout << "Terminating..." << std::endl;
}

static void init(int argc, const char *argv[])
{
    ebpfRetCode rc = ebpf_no_error;
    if(getuid() != 0) {
        throw std::runtime_error("Please run as root user");
    }


    s_ebpf = init_ebpf_flow(NULL, ebpfHandler, &rc, s_flags);
    if(!s_ebpf) {
        throw std::runtime_error(
                std::string("Unable to initialize libebpfflow: ") + ebpf_print_error(rc)
            );
    }
    signal(SIGINT, terminate);
}

static void run()
{
    assert(s_ebpf != NULL);
    while(s_isRun) {
        ebpf_poll_event(s_ebpf, 10);
    }
}

static void done()
{
    assert(s_ebpf != NULL);
    term_ebpf_flow(s_ebpf);
    std::cout << "eBPF terminated" << std::endl;
}


int main(int argc, const char *argv[])
{
    try {
        init(argc, argv);
        run();
        done();
    } catch(const std::exception& err) {
        std::cerr << "Error: " << SOURCE_FILE_LINE << err.what() << std::endl;
        done();
    }
    return 0;
}

static char* intoaV4(unsigned int addr, char* buf, u_short bufLen)
{
    char *cp, *retStr;
    int n;

    cp = &buf[bufLen];
    *--cp = '\0';
    n = 4;
    do {
        u_int byte = addr & 0xff;

        *--cp = byte % 10 + '0';
        byte /= 10;
        if(byte > 0) {
        *--cp = byte % 10 + '0';
        byte /= 10;
        if(byte > 0)
        *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);
    retStr = (char*)(cp+1);
    return retStr;
}

const char* event2String(eBPFevent* e)
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
    return("???");
}

static void IPV4Handler(void* t_bpfctx, eBPFevent *e, struct ipv4_addr_t *event)
{
    char buf1[32], buf2[32];
    std::cout << "[addr: "
              << intoaV4(htonl(event->saddr), buf1, sizeof(buf1))
              << " : "
              << e->sport
              << " <-> "
              << intoaV4(htonl(event->daddr), buf2, sizeof(buf2))
              << " : "
              << e->dport
              << "]"
              << std::endl;
}

static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize)
{
    eBPFevent       event;
    struct timespec tp;

    memcpy(&event, t_data, sizeof(eBPFevent));
    ebpf_preprocess_event(&event);

    clock_gettime(CLOCK_MONOTONIC, &tp);

    std::cout << "[latency "
              << ((float)(tp.tv_nsec-(event.ktime % 1000000000)) / (float)1000)
              << " usec] ";

    std::cout << (unsigned int)event.event_time.tv_sec
              << "."
              << (unsigned int)event.event_time.tv_usec
              << " ";
/*
  printf("[%s][%s][IPv4/%s][pid/tid: %u/%u [%s], uid/gid: %u/%u][father pid/tid: %u/%u [%s], uid/gid: %u/%u]",
	 event.ifname, event.sent_packet ? "Sent" : "Rcvd",
	 (event.proto == IPPROTO_TCP) ? "TCP" : "UDP",
	 event.proc.pid, event.proc.tid,
	 (event.proc.full_task_path == NULL) ? event.proc.task : event.proc.full_task_path,
	 event.proc.uid, event.proc.gid,
	 event.father.pid, event.father.tid,
	 (event.father.full_task_path == NULL) ? event.father.task : event.father.full_task_path,
     event.father.uid, event.father.gid);
*/

    if(event.ip_version == 4) {
        IPV4Handler(t_bpfctx, &event, &event.addr.v4);
    } else {
        std::cerr << "must be IPV6Handler" << std::endl;
    }

    if(event.proto == IPPROTO_TCP) {
        std::cout << "[" << event2String(&event) << "] ";
    }

    if(event.etype == eTCP_CONN) {
        std::cout << "[latency: " << (((float)event.latency_usec)/(float)1000) << " msec]";
    }
    /*
    if(event.container_id[0] != '\0') {
    printf("[containerID: %s]", event.container_id);
    
    if(event.docker.name != NULL)
      printf("[docker_name: %s]", event.docker.name);

    if(event.kube.ns)  printf("[kube_name: %s]", event.kube.name);
    if(event.kube.pod) printf("[kube_pod: %s]",  event.kube.pod);
    if(event.kube.ns)  printf("[kube_ns: %s]",   event.kube.ns);
  }
*/
    std::cout << std::endl;
    ebpf_free_event(&event);
}
