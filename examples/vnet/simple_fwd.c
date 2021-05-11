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

#include "simple_fwd.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "rte_ether.h"
#include "rte_mbuf.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_gre.h"
#include "rte_vxlan.h"
#include "doca_vnf.h"
#include "doca_flow.h"
#include "doca_utils.h"
#include "doca_log.h"
#include "doca_fib.h"
#include "doca_ft.h"
#include "simple_fwd.h"

DOCA_LOG_MODULE(SIMPLE_FWD);
#define SIMPLE_FWD_PORTS (2)
#define SIMPLE_FWD_MAX_FLOWS (8096)

struct simple_fwd_app {

	struct doca_ft *ft;

	struct doca_flow_port *port0;
	struct doca_flow_port *port1;

	struct doca_flow_pipe *p_fwd[SIMPLE_FWD_PORTS];
};

static struct simple_fwd_app *sf_ins;
struct doca_flow_fwd *fwd_tbl_port[2];
bool hairpin = true;

struct sf_entry {
	int total_pkts;
	int total_bytes;
	bool is_hw;
	struct doca_flow_pipe_entry *hw_entry;
};

static void
sf_aged_flow_cb(struct doca_ft_user_ctx *ctx)
{
	struct sf_entry *entry = (struct sf_entry *)&ctx->data[0];

	if (entry->is_hw) {
            doca_flow_rm_entry(0, entry->hw_entry);
            entry->hw_entry = NULL;
	}
}

static int
simple_fwd_create(void)
{
	sf_ins = (struct simple_fwd_app *)malloc(sizeof(struct simple_fwd_app));
	if (sf_ins == NULL) {
		DOCA_LOG_CRIT("failed to allocate GW");
		goto fail_init;
	}

	memset(sf_ins , 0, sizeof(struct simple_fwd_app));
	sf_ins->ft = doca_ft_create(SIMPLE_FWD_MAX_FLOWS, sizeof(struct sf_entry),
				    &sf_aged_flow_cb, NULL);
	if (sf_ins->ft == NULL) {
		DOCA_LOG_CRIT("failed to allocate FT");
		goto fail_init;
	}
	return 0;
fail_init:
	if (sf_ins->ft != NULL)
		free(sf_ins->ft);
	if (sf_ins != NULL)
		free(sf_ins);
	sf_ins = NULL;
	return -1;
}

static struct doca_flow_fwd *
sf_build_port_fwd(struct sf_port_cfg *port_cfg)
{
    struct doca_flow_fwd *fwd = malloc(sizeof(struct doca_flow_fwd));
    memset(fwd,0,sizeof(struct doca_flow_fwd));
    fwd->type = DOCA_FWD_PORT;
    fwd->port.id = port_cfg->port_id;
    return fwd;
}

static struct doca_flow_port *
sf_init_doca_port(struct sf_port_cfg *port_cfg)
{
#define MAX_PORT_STR (128)
	char port_id_str[MAX_PORT_STR];
	struct doca_flow_port_cfg doca_cfg_port;
	struct doca_flow_port *port;
	struct doca_flow_error err = {0};

	snprintf(port_id_str, MAX_PORT_STR, "%d", port_cfg->port_id);
	doca_cfg_port.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	doca_cfg_port.queues = port_cfg->nb_queues;
	doca_cfg_port.devargs = port_id_str;
	doca_cfg_port.priv_data_size = sizeof(struct sf_port_cfg);

	if (port_cfg->port_id >= SIMPLE_FWD_PORTS) {
		DOCA_LOG_ERR("port id exceeds max ports id:%d", SIMPLE_FWD_PORTS);
		return NULL;
	}
	port = doca_flow_port_start(&doca_cfg_port, &err);
	if (port == NULL) {
		DOCA_LOG_ERR("failed to start port %s", err.message);
		return NULL;
	}

	*((struct sf_port_cfg *)doca_flow_port_priv_data(port)) = *port_cfg;
    fwd_tbl_port[port_cfg->port_id] = sf_build_port_fwd(port_cfg);
	return port;
}

static void
build_match_tunnel_5tuple(struct doca_flow_match *match)
{
	match->out_dst_ip.a.ipv4_addr = 0xffffffff;
	match->out_dst_ip.type = DOCA_IPV4;
    match->out_l4_type = IPPROTO_UDP;
	match->out_dst_port = rte_cpu_to_be_16(DOCA_VXLAN_DEFAULT_PORT);

    match->tun.type = DOCA_TUN_VXLAN;
    match->tun.vxlan.tun_id = 0xffffffff;

	match->in_dst_ip.a.ipv4_addr = 0xffffffff;
	match->in_src_ip.a.ipv4_addr = 0xffffffff;
	match->in_src_ip.type = DOCA_IPV4;
	match->in_l4_type = 0x6;

	match->in_src_port = 0xffff;
	match->in_dst_port = 0xffff;
}

static void build_match_5tuple(struct doca_flow_match *match)
{
    match->out_dst_ip.a.ipv4_addr = 0xffffffff;
    match->out_src_ip.a.ipv4_addr = 0xffffffff;
    match->out_src_ip.type = DOCA_IPV4;
    match->out_l4_type = 0x6;

    match->out_src_port = 0xffff;
    match->out_dst_port = 0xffff;
}

static void build_match_tun_and_5tuple(struct doca_flow_match *match)
{
	match->out_dst_ip.a.ipv4_addr = 0xffffffff;
	match->out_dst_ip.type = DOCA_IPV4;

	match->out_l4_type = IPPROTO_UDP;
	match->out_dst_port = rte_cpu_to_be_16(
	    DOCA_VXLAN_DEFAULT_PORT);
	match->tun.type = DOCA_TUN_VXLAN;
	match->tun.vxlan.tun_id = 0xffffffff;

	match->in_dst_ip.a.ipv4_addr = 0xffffffff;
	match->in_src_ip.a.ipv4_addr = 0xffffffff;
	match->in_src_ip.type = DOCA_IPV4;
	match->in_l4_type = 0x6;

	match->in_src_port = 0xffff;
	match->in_dst_port = 0xffff;
}

static void build_decap_action(struct doca_flow_actions *actions)
{
	actions->decap = true;
}

static void build_encap_action(struct doca_flow_actions *actions)
{
	actions->has_encap = true;
	actions->encap.src_ip.a.ipv4_addr =
	    doca_inline_parse_ipv4("111.168.1.2");
	actions->encap.dst_ip.a.ipv4_addr =
		doca_inline_parse_ipv4("111.168.1.1");

	memset(actions->encap.src_mac, 0xff, sizeof(actions->encap.src_mac));
	memset(actions->encap.dst_mac, 0xff, sizeof(actions->encap.src_mac));

	actions->encap.tun.type = DOCA_TUN_VXLAN;
	actions->encap.tun.vxlan.tun_id = 0x42;
}

static struct doca_flow_pipe *
build_fwd_pipe(struct doca_flow_port *port,uint16_t fwd_port_id)
{
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_error err = {0};
	struct doca_flow_match match;
	struct doca_flow_actions actions = {0};
//    struct doca_flow_fwd fwd;
        
	memset(&match, 0x0, sizeof(match));
    //build_match_5tuple(&match);
	build_match_tun_and_5tuple(&match);
    build_decap_action(&actions);
    build_encap_action(&actions);

	pipe_cfg.name = "FWD";
	pipe_cfg.port = port;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;
	pipe_cfg.count = false;
/*    fwd = sf_build_port_fwd
    fwd.type = DOCA_FWD_PORT;
    fwd.port.id = fwd_port_id; 
    fwd.port.hairpin = hairpin;*/

	return doca_flow_create_pipe(&pipe_cfg, fwd_tbl_port[fwd_port_id], &err);
}

static int
sf_init_ports_and_pipes(int ret, struct sf_port_cfg *port_cfg)
{
	struct doca_flow_error err = {0};
	struct doca_flow_cfg cfg = { 
        .total_sessions = SIMPLE_FWD_MAX_FLOWS ,
        .queues = port_cfg->nb_queues
    };

	if (ret)
		return ret;
	/* init doca framework */
	if (doca_flow_init(&cfg, &err)) {
		DOCA_LOG_ERR("failed to init doca:%s", err.message);
		return -1;
	}
	/* define doca ports */
    port_cfg->port_id = 0;
	sf_ins->port0 = sf_init_doca_port(port_cfg);
    port_cfg->port_id = 1;
	sf_ins->port1 = sf_init_doca_port(port_cfg);

	if (sf_ins->port0 == NULL || sf_ins->port1 == NULL) {
		DOCA_LOG_ERR("failed to start port %s", err.message);
		return -1;
	}

        // TBD: find a better way to express
	sf_ins->p_fwd[0] = build_fwd_pipe(sf_ins->port0, 1);
	sf_ins->p_fwd[1] = build_fwd_pipe(sf_ins->port1, 0);

	return 0;
}

static int
simple_fwd_init(void *p)
{
	struct sf_port_cfg *port_cfg = (struct sf_port_cfg *)p;
	int ret = 0;

	ret |= simple_fwd_create();
	ret |= sf_init_ports_and_pipes(ret, port_cfg);

	return ret;
}

static struct doca_flow_pipe_entry *
sf_pipe_add_entry(struct doca_pkt_info *pinfo,
			      struct doca_flow_pipe *pipe)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions = {0};
	struct doca_flow_error err = {0};

	if (pinfo->outer.l3_type != 4) {
		DOCA_LOG_WARN("IPv6 not supported");
		return NULL;
	}

	memset(&match, 0x0, sizeof(match));

	/* exact outer 5-tuple */
	match.out_dst_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_dst(pinfo);
	match.out_src_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_src(pinfo);
	match.out_l4_type = pinfo->outer.l4_type;
	match.out_src_port = doca_pinfo_outer_src_port(pinfo);
	match.out_dst_port = doca_pinfo_outer_dst_port(pinfo);

	match.tun.vxlan.tun_id = pinfo->tun.vni;

	match.in_dst_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_dst(pinfo);
	match.in_src_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_src(pinfo);
	match.in_l4_type = pinfo->inner.l4_type;
	match.in_src_port = doca_pinfo_inner_src_port(pinfo);
	match.in_dst_port = doca_pinfo_inner_dst_port(pinfo);

	actions.has_encap = true;
	actions.encap.src_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_dst(pinfo);
	actions.encap.dst_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_src(pinfo);

	memset(actions.encap.src_mac, 0xaa, sizeof(actions.encap.src_mac));
	memset(actions.encap.dst_mac, 0xbb, sizeof(actions.encap.src_mac));

	actions.encap.tun.type = DOCA_TUN_VXLAN;
	actions.encap.tun.vxlan.tun_id = 0x42;

	return doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL,
                            	    fwd_tbl_port[pinfo->orig_port_id], &err);
}


static int
sf_handle_new_flow(struct doca_pkt_info *pinfo,
    		       struct doca_ft_user_ctx **ctx)
{
	struct sf_entry *entry = NULL;

    switch (pinfo->outer.l4_type) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
            break;
        default:
            return 0;
    };
	
    if (!doca_ft_add_new(sf_ins->ft, pinfo, ctx)) {
        DOCA_LOG_DBG("failed create new entry");
        return -1;
    }
    entry = (struct sf_entry *)&(*ctx)->data[0];
    entry->hw_entry = sf_pipe_add_entry(pinfo, sf_ins->p_fwd[pinfo->orig_port_id]);

    if (entry->hw_entry == NULL) {
        DOCA_LOG_DBG("failed to offload");
        return -1;
    }

    entry->is_hw = true;
    return 0;
}


static int 
sf_handle_packet(struct doca_pkt_info *pinfo)
{
	struct doca_ft_user_ctx *ctx = NULL;
	struct sf_entry *entry = NULL;

	if (!doca_ft_find(sf_ins->ft, pinfo, &ctx)) {
		if (sf_handle_new_flow(pinfo, &ctx))
			return -1;
	}
	entry = (struct sf_entry *)&ctx->data[0];
	entry->total_pkts++;

	return 0;
}

static int sf_destroy(void)
{
    DOCA_LOG_ERR("destroy TBD");
	return 0;
}

struct doca_vnf simple_fwd_vnf = {
	.doca_vnf_init = &simple_fwd_init,
	.doca_vnf_process_pkt = &sf_handle_packet,
	.doca_vnf_destroy = &sf_destroy,
};

struct doca_vnf *simple_fwd_get_doca_vnf(void)
{
	return &simple_fwd_vnf;
}
