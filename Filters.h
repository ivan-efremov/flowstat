/**
 * @file Filters.h
 */
#pragma once

#include <vector>
#include <functional>
#include <memory>
#include "Statistics.h"


typedef std::function<bool(eBPFevent* event)> FilterType;
typedef std::vector<FilterType>               VectorFilters;
typedef std::shared_ptr<VectorFilters>        PVectorFilters;


extern std::string  g_interface;
extern uint64_t     g_srcaddr;
extern uint64_t     g_dstaddr;
extern uint16_t     g_srcport;
extern uint16_t     g_dstport;


/**
 * @brief Фильтр сетевого интерфейса.
 */
struct InterfaceFilter: public FilterType {
    bool operator() (eBPFevent* event) const {
        return g_interface == event->ifname ? true : false;
    }
};


/**
 * @brief Фильтр адреса источника.
 */
struct SrcAddrFilter: public FilterType {
    PStatistic m_stat;
    SrcAddrFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {
        return event->addr.v4.saddr == g_srcaddr ? true : false;
    }
};


/**
 * @brief Фильтр адреса получателя.
 */
struct DstAddrFilter: public FilterType {
    PStatistic m_stat;
    DstAddrFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {
        return event->addr.v4.daddr == g_dstaddr ? true : false;
    }
};


/**
 * @brief Фильтр порта источника.
 */
struct SrcPortFilter: public FilterType {
    PStatistic m_stat;
    SrcPortFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {
        return event->sport == g_srcport ? true : false;
    }
};


/**
 * @brief Фильтр порта получателя.
 */
struct DstPortFilter: public FilterType {
    PStatistic m_stat;
    DstPortFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {
        return event->dport == g_dstport ? true : false;
    }
};


/**
 * @brief Фильтр TCP протокола.
 */
struct TcpProtoFilter: public FilterType {
    PStatistic m_stat;
    TcpProtoFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {

        return true;
    }
};


/**
 * @brief Фильтр UDP протокола.
 */
struct UdpProtoFilter: public FilterType {
    PStatistic m_stat;
    UdpProtoFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {

        return true;
    }
};


/**
 * @brief Фильтр TCP+UDP протокола.
 */
struct AnyProtoFilter: public FilterType {
    PStatistic m_stat;
    AnyProtoFilter(PStatistic stat): m_stat(stat) {
    }
    bool operator() (eBPFevent* event) const {

        return true;
    }
};
