/**
 * @file Statistics.h
 */
#pragma once

#include <cstdint>
#include <functional>
#include <vector>
#include <memory>
#include "ebpf_flow.h"


/**
 * @short Статистика пакетов.
 */
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
