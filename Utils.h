/**
 * @file Utils.h
 */
#pragma once

#include <string>
#include <cstdint>

#define SOURCE_FILE_LINE    (std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": ")

extern uint64_t     str2ip(const std::string& str);
extern std::string  ip2str(uint32_t addr);
