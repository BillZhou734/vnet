#include "doca_gw.h"
#include "gw.h"
#include "doca_log.h"
#include "doca_gw_dpdk.h"
#include "doca_dpdk_priv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DOCA_LOG_MODULE(doca_gw);

struct doca_fwd_tbl {
    const char * name;
    void * handler;
    uint32_t id;
    struct doca_fwd_table_cfg cfg;
};

uint8_t *doca_gw_port_priv_data(struct doca_gw_port *p)
{
    return &p->user_data[0];
}

int doca_gw_init(struct doca_gw_cfg *cfg,struct doca_gw_error *err)
{
    DOCA_LOG_INFO("total sessions = %d\n",cfg->total_sessions);
    if (err) {
        *err = *err;
    }
    doca_gw_init_dpdk(cfg);
    return 0;
}


/**
 * @brief 
 *
 * @param match
 *
 * @return 
 */
struct doca_gw_pipelne_entry *doca_gw_pipeline_add_entry(uint16_t pipe_queue, 
                      struct doca_gw_pipeline *pipeline, struct doca_gw_match *match,
                      struct doca_gw_actions *actions,struct doca_gw_monitor *mon,
                      struct doca_fwd_tbl *fwd, struct doca_gw_error *err)
{
    if(pipeline == NULL || match == NULL || actions == NULL || mon == NULL)
        return NULL;
	pipe_queue = pipe_queue;
	return doca_gw_dpdk_pipe_create_flow(pipeline, match, actions, mon, &fwd->cfg, err);
}

int doca_gw_rm_entry(uint16_t pipe_queue, struct doca_gw_pipelne_entry *entry)
{
    DOCA_LOG_INFO("(pipe %d) HW release id%d",pipe_queue, entry->id);
	// TODO: how to get the port id?
	//doca_gw_dpdk_free_flow(0, entry->pipe_entry);
    free(entry);
    return 0;
}

/**
 * @brief 
 *
 * @param cfg
 * @param port
 *
 * @return 
 */
struct doca_gw_port * doca_gw_port_start(struct doca_gw_port_cfg *cfg, struct doca_gw_error *err)
{
	struct doca_gw_port *port = NULL;

	if (cfg == NULL)
		return NULL;
	switch(cfg->type) {
	case DOCA_GW_PORT_DPDK:
		DOCA_LOG_INFO("port is dpdk, matching port id");
		// init all required data sturcures for port.
		break;
	case DOCA_GW_PORT_DPDK_BY_ID:
		//TODO: need to parse devargs
		DOCA_LOG_INFO("new doca port type:dpdk port id:%s", cfg->devargs);
		cfg->port_id = atoi(cfg->devargs);
		port = doca_gw_dpdk_port_start(cfg, err);
		break;
	default:
		DOCA_LOG_ERR("unsupported port type");
		err->message = "unsupported port type";
		return NULL;
	}
	return port;
}

/**
 * @brief - close port
 *  release all resources used by port, including all HW rules.
 *
 * @param port
 *
 * @return 
 */
int doca_gw_port_stop(struct doca_gw_port *port)
{
    if (port != NULL) {
       printf("port id = %d stopped\n", port->port_id); 
    }
    return 0;
}

struct doca_gw_pipeline *doca_gw_create_pipe(struct doca_gw_pipeline_cfg *cfg, struct doca_gw_error *err)
{
	if (cfg == NULL)
		return NULL;
	return doca_gw_dpdk_create_pipe(cfg, err);
}

void doca_gw_destroy(uint16_t port_id)
{
	doca_gw_dpdk_destroy(port_id);
}

void doca_gw_dump_pipeline(uint16_t port_id)
{
	doca_gw_dpdk_dump_pipeline(port_id);
}

struct doca_fwd_tbl *doca_gw_create_fwd_tbl(struct doca_fwd_table_cfg *cfg)
{
    static uint32_t fwd_id = 0;
    struct doca_fwd_tbl *tbl = malloc(sizeof(struct doca_fwd_tbl));
    memset(tbl, 0, sizeof(struct doca_fwd_tbl));
    tbl->cfg = *cfg;
    tbl->id = fwd_id++;
    DOCA_LOG_INFO("add fwd tbl");
    return tbl;
}
