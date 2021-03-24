#ifndef _DOCA_DPDK_PRIV_H_
#define _DOCA_DPDK_PRIV_H_

struct doca_gw_pipelne_entry {
	LIST_ENTRY(doca_gw_pipelne_entry) next;
    int id;
    void *pipe_entry;
    /* for deletion */
    int meter_id;
    int meter_profile_id;
};

struct doca_gw_pipeline {
	LIST_ENTRY(doca_gw_pipeline) next;
    void * handler;
	uint32_t id;
	uint32_t pipe_entry_id;
	struct doca_gw_pipe_dpdk_flow flow;
	LIST_HEAD(, doca_gw_pipelne_entry) entry_list;
};

struct doca_gw_port
{
    uint32_t port_id;
    int      idx;

	LIST_HEAD(, doca_gw_pipeline) pipe_list;
    uint8_t  user_data[0];
};

#endif
