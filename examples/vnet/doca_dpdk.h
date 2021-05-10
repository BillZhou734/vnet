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

#ifndef _DOCA_DPDK_H_
#define _DOCA_DPDK_H_

#include <stdio.h>
#include <rte_flow.h>
#include "doca_flow.h"
#include "doca_utils.h"

#define DOCA_GET_SRC_IP(match, type)                                           \
	((type == OUTER_MATCH) ? match->out_src_ip : match->in_src_ip)
#define DOCA_GET_DST_IP(match, type)                                           \
	((type == OUTER_MATCH) ? match->out_dst_ip : match->in_dst_ip)
#define DOCA_GET_SPORT(match, type)                                            \
	((type == OUTER_MATCH) ? match->out_src_port : match->in_src_port)
#define DOCA_GET_DPORT(match, type)                                            \
	((type == OUTER_MATCH) ? match->out_dst_port : match->in_dst_port)

#define INNER_MATCH 1
#define OUTER_MATCH 2
#define MAX_ITEMS 12
#define MAX_ACTIONS 12
#define MAX_PIP_FLOWS 20
#define MAX_FLOW_FRIO 3

enum ACTION_DIRECTION {
	DOCA_SRC = 1,
	DOCA_DST,
};

enum DOCA_TUNNEL_ACTION_TYPE {
	DOCA_ENCAP,
	DOCA_DECAP,
};

struct doca_dpdk_item_eth_data {
	struct rte_flow_item_eth spec;
	struct rte_flow_item_eth last;
	struct rte_flow_item_eth mask;
};

struct doca_dpdk_item_vlan_data {
	struct rte_flow_item_vlan spec;
	struct rte_flow_item_vlan last;
	struct rte_flow_item_vlan mask;
};

struct doca_dpdk_item_ipv4_data {
	uint8_t match_layer;
	struct rte_flow_item_ipv4 spec;
	struct rte_flow_item_ipv4 last;
	struct rte_flow_item_ipv4 mask;
};

struct doca_dpdk_item_ipv6_data {
	uint8_t match_layer;
	struct rte_flow_item_ipv6 spec;
	struct rte_flow_item_ipv6 last;
	struct rte_flow_item_ipv6 mask;
};

struct doca_dpdk_item_vxlan_data {
	struct rte_flow_item_vxlan spec;
	struct rte_flow_item_vxlan last;
	struct rte_flow_item_vxlan mask;
};

struct doca_dpdk_item_gre_data {
	struct rte_flow_item_gre spec;
	struct rte_flow_item_gre last;
	struct rte_flow_item_gre mask;
};

struct doca_dpdk_item_gre_key_data {
	uint32_t spec;
	uint32_t last;
	uint32_t mask;
};

struct doca_dpdk_item_udp_data {
	uint8_t match_layer;
	struct rte_flow_item_udp spec;
	struct rte_flow_item_udp last;
	struct rte_flow_item_udp mask;
};

struct doca_dpdk_item_tcp_data {
	uint8_t match_layer;
	struct rte_flow_item_tcp spec;
	struct rte_flow_item_tcp last;
	struct rte_flow_item_tcp mask;
};

struct doca_dpdk_item_data {
	union {
		struct doca_dpdk_item_eth_data eth;
		struct doca_dpdk_item_vlan_data vlan;
		struct doca_dpdk_item_ipv4_data ipv4;
		struct doca_dpdk_item_ipv6_data ipv6;
		struct doca_dpdk_item_vxlan_data vxlan;
		struct doca_dpdk_item_tcp_data tcp;
		struct doca_dpdk_item_udp_data udp;
		struct doca_dpdk_item_gre_data gre;
		struct doca_dpdk_item_gre_key_data gre_key;
	};
};

struct doca_dpdk_item_entry {
	uint8_t flags;
	struct rte_flow_item *item;
	struct doca_dpdk_item_data item_data;
	int (*modify_item)(struct doca_dpdk_item_entry *entry,
		struct doca_flow_match *match, struct doca_flow_match *mask);
};

struct doca_dpdk_action_mac_data {
	struct rte_flow_action_set_mac set_mac;
};

struct doca_dpdk_action_jump_data {
	struct rte_flow_action_jump jump;
};

struct doca_dpdk_action_ipv4_addr_data {
	struct rte_flow_action_set_ipv4 ipv4;
};

struct doca_dpdk_action_rss_data {
	struct rte_flow_action_rss conf;
	uint8_t key[40];
	uint16_t queue[128];
};

struct doca_dpdk_action_rawdecap_data {
	struct rte_flow_action_raw_decap conf;
	uint8_t data[128];
	uint16_t idx;
};

struct doca_dpdk_action_rawencap_data {
	struct rte_flow_action_raw_encap conf;
	uint8_t data[128];
	uint8_t preserve[128];
	uint16_t idx;
};

struct doca_dpdk_action_meter_data {
	uint32_t prof_id;
	uint32_t policy_id;
	struct rte_flow_action_meter conf;
};

struct doca_dpdk_action_l4_port_data {
	struct rte_flow_action_set_tp l4port;
};

struct doca_dpdk_action_fwd_data {
    struct rte_flow_action_queue queue_conf;
    struct rte_flow_action_port_id port_id_conf;
};

struct doca_dpdk_action_data {
	union {
		struct doca_dpdk_action_jump_data jump;
		struct doca_dpdk_action_mac_data mac;
		struct doca_dpdk_action_ipv4_addr_data ipv4;
		struct doca_dpdk_action_l4_port_data l4port;
		struct doca_dpdk_action_rss_data rss;
		struct doca_dpdk_action_rawdecap_data rawdecap;
		struct doca_dpdk_action_rawencap_data rawencap;
		struct doca_dpdk_action_meter_data meter;
        struct doca_dpdk_action_fwd_data fwd;
	};
};

struct doca_dpdk_action_entry {
	struct rte_flow_action *action;
	struct doca_dpdk_action_data action_data;
	int (*modify_action)(struct doca_dpdk_action_entry *entry,
		struct doca_flow_actions *action);
};

struct doca_dpdk_pipe {
	uint16_t port_id;
	uint8_t nb_items;
	uint8_t nb_actions_pipe;
	uint8_t nb_actions_entry;
	uint32_t meter_info; /*profile id = policy id*/
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS];
	struct doca_dpdk_item_entry item_entry[MAX_ITEMS];
	struct rte_flow_action actions[MAX_ACTIONS];
	struct doca_dpdk_action_entry action_entry[MAX_ACTIONS];
	LIST_ENTRY(doca_dpdk_pipe) free_list;
};

struct doca_dpdk_pipe_list {
	struct doca_dpdk_pipe pipe_flows[MAX_PIP_FLOWS];
	LIST_HEAD(, doca_dpdk_pipe) free_head;
};

struct endecap_layer {
	uint16_t layer;
	void (*fill_data)(uint8_t **, struct doca_flow_pipe_cfg *, uint8_t);
};

enum DOCA_DECAP_HDR {
	FILL_ETH_HDR = (1 << 0),
	FILL_IPV4_HDR = (1 << 1),
	FILL_UDP_HDR = (1 << 2),
	FILL_VXLAN_HDR = (1 << 3),
	FILL_GRE_HDR = (1 << 4),
};

/*need move to util file ??*/
static inline bool doca_is_mac_zero(void *mac_addr)
{
	uint16_t *addr = mac_addr;
	return (addr[0] | addr[1] | addr[2]) == 0;
}

static inline void doca_set_mac_max(void *mac_addr)
{
	uint16_t *addr = mac_addr;

	addr[0] = UINT16_MAX;
	addr[1] = UINT16_MAX;
	addr[2] = UINT16_MAX;
}

static inline void doca_mac_copy(uint8_t *from, struct rte_ether_addr *to)
{
	rte_ether_addr_copy((const struct rte_ether_addr *)from, to);
}

static inline bool doca_is_mac_max(void *mac_addr)
{
	uint16_t *addr = mac_addr;
	return addr[0] == UINT16_MAX && addr[1] == UINT16_MAX &&
	       addr[2] == UINT16_MAX;
}

static inline bool doca_is_ip_zero(struct doca_ip_addr *ip_addr)
{
	uint64_t *addr = (uint64_t *)(&ip_addr->a);
	if (ip_addr->type == DOCA_IPV6)
		return addr[0] == 0 && addr[1] == 0;
	return ip_addr->a.ipv4_addr == 0;
}

static inline bool doca_is_ip_max(struct doca_ip_addr *ip_addr)
{
	uint64_t *addr = (uint64_t *)(&ip_addr->a);
	if (ip_addr->type == DOCA_IPV6)
		return addr[0] == UINT64_MAX && addr[1] == UINT64_MAX;
	return ip_addr->a.ipv4_addr == UINT32_MAX;
}

static inline void doca_set_item_ipv6_max(void *ip6_addr)
{
	uint64_t *addr = (uint64_t *)ip6_addr;
	addr[0] = UINT64_MAX;
	addr[1] = UINT64_MAX;
}

static inline void doca_set_item_vni_max(void *vni)
{
	uint8_t *addr = (uint8_t *)vni;
	addr[0] = UINT8_MAX;
	addr[1] = UINT8_MAX;
	addr[2] = UINT8_MAX;
}

static inline bool doca_match_is_ipv4(struct doca_flow_match *match,
				      uint8_t type)
{
	struct doca_ip_addr ip_addr;

	// need confim: must set src or dst;
	if (type == INNER_MATCH)
		ip_addr = match->in_src_ip.type != DOCA_NONE ? match->in_src_ip
							     : match->in_dst_ip;
	else
		ip_addr = match->out_src_ip.type != DOCA_NONE
			      ? match->out_src_ip
			      : match->out_dst_ip;
	return (ip_addr.type == DOCA_IPV4);
}

static inline rte_be16_t doca_dpdk_get_l3_protol(struct doca_flow_match *match,
						 uint8_t type)
{
	uint16_t protocol;
	if (type == OUTER_MATCH && match->vlan_id)
		protocol = RTE_ETHER_TYPE_VLAN;
	else
		protocol = doca_match_is_ipv4(match, type)
			       ? RTE_ETHER_TYPE_IPV4
			       : RTE_ETHER_TYPE_IPV6;
	return rte_cpu_to_be_16(protocol);
}

static inline bool doca_match_is_tcp(struct doca_flow_match *match)
{
	if (match->tun.type == DOCA_TUN_NONE)
		return (match->out_l4_type == IPPROTO_TCP);
	return (match->in_l4_type == IPPROTO_TCP);
}

static inline bool doca_match_is_udp(struct doca_flow_match *match)
{
	if (match->tun.type == DOCA_TUN_NONE)
		return (match->out_l4_type == IPPROTO_UDP);
	return (match->in_l4_type == IPPROTO_UDP);
}

void doca_dpdk_init(struct doca_flow_cfg *cfg);

struct doca_flow_pipe *
doca_dpdk_create_pipe(struct doca_flow_pipe_cfg *cfg,
                      struct doca_flow_fwd *fwd,
		      struct doca_flow_error *err);

struct doca_flow_pipe_entry *doca_dpdk_pipe_create_flow(
	struct doca_flow_pipe *pipe, uint16_t pipe_queue,
        struct doca_flow_match *match, struct doca_flow_match *match_mask,
	struct doca_flow_actions *actions, struct doca_flow_monitor *mon,
	struct doca_flow_fwd *cfg, struct doca_flow_error *err);

int doca_dpdk_init_port(uint16_t port_id);
int doca_dpdk_pipe_free_entry(uint16_t portid,
			      struct doca_flow_pipe_entry *entry);

struct doca_flow_port *doca_dpdk_port_start(struct doca_flow_port_cfg *cfg,
					    struct doca_flow_error *err);
void doca_dpdk_destroy(uint16_t port_id);
void doca_dpdk_dump_pipe(uint16_t port_id);

void doca_dpdk_enable_acl(void);

#endif
