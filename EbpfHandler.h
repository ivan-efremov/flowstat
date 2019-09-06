/**
 * @file EbpfHandler.h
 */
#pragma once

#include <bcc/BPF.h>
#include "ebpf_flow.h"

struct sock_stats {
    struct sock *sk;
    u64    ts;
};

extern void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);
