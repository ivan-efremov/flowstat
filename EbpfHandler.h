/**
 * @file EbpfHandler.h
 */
#pragma once

#include <bcc/BPF.h>
#include "ebpf_flow.h"

extern void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);
