#ifndef _DOCA_DPDK_PRIV_H_
#define _DOCA_DPDK_PRIV_H_

struct doca_gw_pipelne_entry {
	LIST_ENTRY(doca_gw_pipelne_entry) next;
    int id;
    void *pipe_entry;
    uint32_t meter_id;
	uint32_t meter_policy_id;
    uint32_t meter_profile_id;
};

#define TMP_BUFF 128
struct doca_gw_pipeline {
	LIST_ENTRY(doca_gw_pipeline) next;
	char name[TMP_BUFF];
    void * handler;
	uint32_t id;
	uint32_t pipe_entry_id;
	uint32_t nb_pipe_entrys;
	struct doca_gw_pipe_dpdk_flow flow;
	rte_spinlock_t entry_lock;
	LIST_HEAD(, doca_gw_pipelne_entry) entry_list;
};

struct doca_flow_port
{
    uint32_t port_id;
    int      idx;

	rte_spinlock_t pipe_lock;
	LIST_HEAD(, doca_gw_pipeline) pipe_list;
    uint8_t  user_data[0];
};

#endif
