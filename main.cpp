#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <boost/program_options.hpp>
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <climits>
#include <cassert>
#include <functional>
#include <vector>
#include <memory>
#include <bcc/BPF.h>
#include "ebpf_flow.h"

#define SOURCE_FILE_LINE    (std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": ")


typedef std::function<bool(eBPFevent* event)> FilterType;
typedef std::vector<FilterType>               VectorFilters;
typedef std::shared_ptr<VectorFilters>        PVectorFilters;

struct Statistic {
    time_t   lastTime = 0;   ///< время обновления статистики
    uint64_t packets  = 0;   ///< общее количество принятых пакетов
    uint64_t bytes    = 0;   ///< общее количество принятых байт
    double   avrSpeed = 0.0; ///< средняя скорость от начала работы утилиты (в Мбит/с)
    double   minSpeed = 0.0; ///< минимальное значение скорости за 1-секундный интервал (в Мбит/с)
    double   maxSpeed = 0.0; ///< максимальное значение скорости за 1-секундный интервал (в Мбит/с)
};
typedef std::shared_ptr<Statistic>         PStatistic;
typedef std::vector<PStatistic>            VectorStatistics;
typedef std::shared_ptr<VectorStatistics>  PVectorStatistics;


static int               s_isRun = true;
static void             *s_ebpf = NULL;
static short             s_flags = 0;
static uint64_t          s_srcaddr = 0;
static uint64_t          s_dstaddr = 0;
static uint16_t          s_srcport = 0;
static uint16_t          s_dstport = 0;
static uint64_t          s_flushStat = 0;
static std::string       s_interface;
static PVectorFilters    s_filters = std::make_shared<VectorFilters>();
static PVectorStatistics s_statistics = std::make_shared<VectorStatistics>();


static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);


static uint64_t str2ip(const std::string& str)
{
    struct sockaddr_in sa;
    if(0 == inet_pton(AF_INET, str.c_str(), &sa.sin_addr)) {
        return 0UL;
    }
    return uint64_t(ntohl(sa.sin_addr.s_addr));
}

static std::string ip2str(uint32_t addr)
{
    std::string str;
    str.reserve(16);
    str += std::to_string(addr >> 24 & 0xFF) + '.';
    str += std::to_string(addr >> 16 & 0xFF) + '.';
    str += std::to_string(addr >> 8  & 0xFF) + '.';
    str += std::to_string(addr & 0xFF);
    return str;
}

static void terminate(int sig)
{
    s_isRun = false;
    std::cout << "Terminating..." << std::endl;
}

static void init(int argc, const char *argv[])
{
    namespace po = boost::program_options;

    ebpfRetCode             rc(ebpf_no_error);
    po::variables_map       vm;
    po::options_description desc("Usage");
    try {
        desc.add_options()
            ("help,h",     "Help message")
            ("version,v",  "Program version")
            ("interface,i",po::value<std::string>(), "The name of the interface: eth0/ppp0 and etc...")
            ("srcaddr,s",  po::value<std::string>(), "Source address: xxx.xxx.xxx.xxx")
            ("dstaddr,d",  po::value<std::string>(), "Destination address: xxx.xxx.xxx.xxx")
            ("srcport,k",  po::value<uint16_t>(),    "Source port: [1 - 65535]")
            ("dstport,o",  po::value<uint16_t>(),    "Destination port: [1 - 65535]")
            ("proto,p",    po::value<std::string>(), "Protocols: tcp/udp/all")
            ("flush,f",    po::value<uint64_t>(),    "Flush statistics: in milliseconds");
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch(const std::exception& err) {
         throw std::runtime_error(SOURCE_FILE_LINE + err.what());
    }
    if(vm.count("help") || argc == 1 ) {
        std::cout << desc
                  << "\nExample:\n\t./flowstat -i ens32 -s 4.4.8.8 -k 53 -p all\n"
                  << std::endl;
        exit(0);
    }
    if(vm.count("version")) {
        std::cout << "0.0.2-" << __DATE__ << std::endl;
        exit(0);
    }
    if(vm.count("interface")) {
        s_interface = vm["interface"].as<std::string>();
        s_filters->emplace_back([](eBPFevent* event) {
            return s_interface == event->ifname ? true : false;
        });
    }
    if(vm.count("srcaddr")) {
        auto statistic = std::make_shared<Statistic>();
        s_statistics->push_back(statistic);
        s_srcaddr = str2ip(vm["srcaddr"].as<std::string>());
        s_filters->emplace_back([statistic](eBPFevent* event) {

            return event->addr.v4.saddr == s_srcaddr ? true : false;
        });
    }
    if(vm.count("dstaddr")) {
        auto statistic = std::make_shared<Statistic>();
        s_statistics->push_back(statistic);
        s_dstaddr = str2ip(vm["dstaddr"].as<std::string>());
        s_filters->emplace_back([statistic](eBPFevent* event) {

            return event->addr.v4.daddr == s_dstaddr ? true : false;
        });
    }
    if(vm.count("srcport")) {
        s_srcport = vm["srcport"].as<uint16_t>();
        s_filters->emplace_back([](eBPFevent* event) {
            return event->sport == s_srcport ? true : false;
        });
    }
    if(vm.count("dstport")) {
        s_dstport = vm["dstport"].as<uint16_t>();
        s_filters->emplace_back([](eBPFevent* event) {
            return event->dport == s_dstport ? true : false;
        });
    }
    if(vm.count("proto")) {
        const std::string proto = vm["proto"].as<std::string>();
        if(proto == "tcp") {
            s_flags |= LIBEBPF_TCP | LIBEBPF_TCP_CLOSE | LIBEBPF_TCP_RETR;
        } else if(proto == "udp") {
           s_flags |= LIBEBPF_UDP;
        } else if(proto == "all") {
           s_flags |= LIBEBPF_UDP | LIBEBPF_TCP | LIBEBPF_TCP_CLOSE | LIBEBPF_TCP_RETR;
        } else {
            throw std::runtime_error("Invalid argument 'proto'");
        }
    }
    if(vm.count("flush")) {
       s_flushStat = vm["flush"].as<uint64_t>();
       //....
    }
    if(getuid() != 0) {
        throw std::runtime_error("Please run as root user");
    }
    s_flags |= LIBEBPF_INCOMING;
    s_ebpf = init_ebpf_flow(NULL, ebpfHandler, &rc, s_flags);
    if(!s_ebpf) {
        throw std::runtime_error(
                std::string("Unable to initialize libebpfflow: ") + ebpf_print_error(rc)
            );
    }
    signal(SIGINT,  terminate);
    signal(SIGTERM, terminate);
    signal(SIGQUIT, terminate);
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
    if(s_ebpf) {
        term_ebpf_flow(s_ebpf);
    }
    std::cout << "eBPF terminated" << std::endl;
}


int main(int argc, const char *argv[])
{
    try {
        init(argc, argv);
        run();
        done();
    } catch(const std::exception& err) {
        done();
        std::cerr << "Error: " << SOURCE_FILE_LINE << err.what() << std::endl;
    }
    return 0;
}

std::string event2String(eBPFevent* e)
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

static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize)
{
    eBPFevent       event;
    bool            isMatch = true;

    memcpy(&event, t_data, sizeof(eBPFevent));
    ebpf_preprocess_event(&event);

    for(auto &f : *s_filters) {
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
