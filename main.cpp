/**
 * @short Фильтрация пакетов со сбором статистики.
 * @file main.cpp
 */

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <climits>
#include <cassert>
#include <memory>
#include <unistd.h>
#include <signal.h>
#include "EbpfHandler.h"
#include "Filters.h"
#include "Statistics.h"
#include "Utils.h"


static int        s_isRun = true;
static short      s_flags = 0;

void             *g_ebpf = NULL;
uint64_t          g_srcaddr = 0;
uint64_t          g_dstaddr = 0;
uint16_t          g_srcport = 0;
uint16_t          g_dstport = 0;
uint64_t          g_flushStat = 0;
std::string       g_interface;
PVectorFilters    g_filters = std::make_shared<VectorFilters>();
PVectorStatistics g_statistics = std::make_shared<VectorStatistics>();


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
            ("proto,p",    po::value<std::string>(), "Protocols: tcp/udp/any")
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
        g_interface = vm["interface"].as<std::string>();
        g_filters->push_back(InterfaceFilter());
    }
    if(vm.count("srcaddr")) {
        auto statistic = std::make_shared<Statistic>();
        g_statistics->push_back(statistic);        
        g_srcaddr = str2ip(vm["srcaddr"].as<std::string>());
        g_filters->push_back(SrcAddrFilter(statistic));
    }
    if(vm.count("dstaddr")) {
        auto statistic = std::make_shared<Statistic>();
        g_statistics->push_back(statistic);
        g_dstaddr = str2ip(vm["dstaddr"].as<std::string>());
        g_filters->push_back(DstAddrFilter(statistic));
    }
    if(vm.count("srcport")) {
        auto statistic = std::make_shared<Statistic>();
        g_statistics->push_back(statistic);
        g_srcport = vm["srcport"].as<uint16_t>();
        g_filters->push_back(SrcPortFilter(statistic));
    }
    if(vm.count("dstport")) {
        auto statistic = std::make_shared<Statistic>();
        g_statistics->push_back(statistic);
        g_dstport = vm["dstport"].as<uint16_t>();
        g_filters->push_back(DstPortFilter(statistic));
    }
    if(vm.count("proto")) {
        auto statistic = std::make_shared<Statistic>();
        g_statistics->push_back(statistic);
        const std::string proto = vm["proto"].as<std::string>();
        if(proto == "tcp") {
            s_flags |= LIBEBPF_TCP | LIBEBPF_TCP_CLOSE | LIBEBPF_TCP_RETR;
            g_filters->push_back(TcpProtoFilter(statistic));
        } else if(proto == "udp") {
           s_flags |= LIBEBPF_UDP;
           g_filters->push_back(UdpProtoFilter(statistic));
        } else if(proto == "any") {
           s_flags |= LIBEBPF_UDP | LIBEBPF_TCP | LIBEBPF_TCP_CLOSE | LIBEBPF_TCP_RETR;
           g_filters->push_back(AnyProtoFilter(statistic));
        } else {
            throw std::runtime_error("Invalid argument 'proto'");
        }
    }
    if(vm.count("flush")) {
       g_flushStat = vm["flush"].as<uint64_t>();
       //....
    }
    if(getuid() != 0) {
        throw std::runtime_error("Please run as root user");
    }
    s_flags |= LIBEBPF_INCOMING;
    g_ebpf = init_ebpf_flow(NULL, ebpfHandler, &rc, s_flags);
    if(!g_ebpf) {
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
    assert(g_ebpf != NULL);
    while(s_isRun) {
        ebpf_poll_event(g_ebpf, 10);
    }
}

static void done()
{
    term_ebpf_flow(g_ebpf);
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
