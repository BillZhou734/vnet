/*
 * Copyright (C) 2021 Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software
 * product, including all associated intellectual property rights, are and
 * shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef _DOCA_DPDK_PRIV_H_
#define _DOCA_DPDK_PRIV_H_

#include "doca_dpdk.h"
#include "doca_flow.h"

/*struct doca_flow_fwd_tbl {
	const char *name;
	void *handler;
	uint32_t id;
	struct doca_flow_fwd cfg;
};*/


struct doca_flow_pipe_entry {
	LIST_ENTRY(doca_flow_pipe_entry) next;
	int id;
	uint32_t meter_id;
	void *pipe_entry;
};

#define TMP_BUFF 128
struct doca_flow_pipe {
	LIST_ENTRY(doca_flow_pipe) next;
	char name[TMP_BUFF];
	void *handler;
	uint32_t id;
	uint32_t pipe_entry_id;
	uint32_t nb_pipe_entrys;
	struct doca_flow_fwd fwd;/*when pipe create*/
	struct doca_dpdk_pipe flow;
	rte_spinlock_t entry_lock;
	LIST_HEAD(, doca_flow_pipe_entry) entry_list[0];
};

struct doca_flow_port {
	uint32_t port_id;
	int idx;

	rte_spinlock_t pipe_lock;
	LIST_HEAD(, doca_flow_pipe) pipe_list;
	uint8_t user_data[0];
};

#endif
