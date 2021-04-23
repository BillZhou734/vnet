#include <stdio.h>
#include "doca_gw_dpdk.h"
#include "doca_dpdk_priv.h"
#include "doca_debug_dpdk.h"
#include "doca_log.h"
#include "doca_id_pool.h"
#include <rte_vxlan.h>
#include <rte_ethdev.h>
#include <rte_mtr.h>
#include <rte_gre.h>

DOCA_LOG_MODULE(doca_gw_dpdk);

#define DOCA_GET_SRC_IP(match, type) ((type == OUTER_MATCH) ? match->out_src_ip : match->in_src_ip) 
#define DOCA_GET_DST_IP(match, type) ((type == OUTER_MATCH) ? match->out_dst_ip : match->in_dst_ip)
#define DOCA_GET_SPORT(match, type) ((type == OUTER_MATCH) ? match->out_src_port : match->in_src_port)
#define DOCA_GET_DPORT(match, type) ((type == OUTER_MATCH) ? match->out_dst_port : match->in_dst_port)

//TODO move this code later

struct doca_gw_engine {
    struct doca_id_pool *meter_pool;
    struct doca_id_pool *meter_profile_pool;
};

struct doca_gw_engine doca_gw_engine;
#define DOCA_GW_MAX_PORTS (128)
static struct doca_gw_port *doca_gw_used_ports[DOCA_GW_MAX_PORTS];

void doca_gw_init_dpdk(__rte_unused struct doca_gw_cfg *cfg)
{
	struct doca_id_pool_cfg pool_cfg = { .size = cfg->total_sessions, .min = 1 };
	memset(&doca_gw_engine,0, sizeof(doca_gw_engine));
	memset(doca_gw_used_ports,0,sizeof(doca_gw_used_ports));
	doca_gw_engine.meter_pool = doca_id_pool_create(&pool_cfg);
	doca_gw_engine.meter_profile_pool = doca_id_pool_create(&pool_cfg);
	//todo, need remove to init_port 
	doca_gw_dpdk_init_port(0);
	doca_gw_dpdk_init_port(1);
}

static int
doca_gw_dpdk_modify_eth_item(struct doca_dpdk_item_entry *entry,
									struct doca_gw_match *match)
{
	struct rte_flow_item_eth *spec = &entry->item_data.eth.spec;

	if ((entry->flags & DOCA_MODIFY_SMAC) && !doca_is_mac_zero(match->out_src_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &spec->src);
	if ((entry->flags & DOCA_MODIFY_DMAC) && !doca_is_mac_zero(match->out_dst_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_dst_mac, &spec->dst);
	return 0;
}

static void
doca_gw_dpdk_build_eth_flow_item(struct doca_dpdk_item_entry *entry,
					struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_eth *spec = &entry->item_data.eth.spec;
	struct rte_flow_item_eth *mask = &entry->item_data.eth.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_ETH;
	if (!doca_is_mac_zero(match->out_src_mac)) {
		doca_set_mac_max(mask->src.addr_bytes);
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &spec->src);
		if (doca_is_mac_max(match->out_src_mac))
			entry->flags |= DOCA_MODIFY_SMAC;
	}
	if (!doca_is_mac_zero(match->out_dst_mac)) {
		doca_set_mac_max(mask->dst.addr_bytes);
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_dst_mac, &spec->dst);
		if (doca_is_mac_max(match->out_dst_mac))
			entry->flags |= DOCA_MODIFY_DMAC;
	}
	if (match->vlan_id)
		spec->has_vlan = 1;//will debug if this set is need.
	spec->type = doca_gw_get_l3_protol(match, OUTER_MATCH);
	mask->type = UINT16_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_eth_item;
}

static int
doca_gw_dpdk_modify_vlan_item(struct doca_dpdk_item_entry *entry,
									struct doca_gw_match *match)
{
	struct rte_flow_item_vlan *spec = &entry->item_data.vlan.spec;

	if ((entry->flags & DOCA_MODIFY_VLAN_ID) && match->vlan_id)
		spec->tci = RTE_BE16(match->vlan_id);
	return 0;
}

static void
doca_gw_dpdk_build_vlan_item(__rte_unused struct doca_dpdk_item_entry *entry,
					__rte_unused struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_vlan *spec = &entry->item_data.vlan.spec;
	struct rte_flow_item_vlan *mask = &entry->item_data.vlan.mask;

	if (!match->vlan_id)
		return;
	flow_item->type = RTE_FLOW_ITEM_TYPE_VLAN;
	spec->tci = RTE_BE16(match->vlan_id);
	flow_item->spec = spec;
	flow_item->spec = mask;
	if (match->vlan_id == UINT16_MAX) {
		entry->flags |= DOCA_MODIFY_VLAN_ID;
		entry->modify_item = doca_gw_dpdk_modify_vlan_item;
	}
}

static int
doca_gw_dpdk_modify_ipv4_item(struct doca_dpdk_item_entry *entry,
									struct doca_gw_match *match)
{
	uint8_t layer = entry->item_data.ipv4.match_layer;
	struct rte_flow_item_ipv4 *spec = &entry->item_data.ipv4.spec;
	struct doca_ip_addr src_ip = DOCA_GET_SRC_IP(match, layer);
	struct doca_ip_addr dst_ip = DOCA_GET_DST_IP(match, layer);

	if ((entry->flags & DOCA_MODIFY_SIP) && src_ip.a.ipv4_addr)
		spec->hdr.src_addr = src_ip.a.ipv4_addr;
	if ((entry->flags & DOCA_MODIFY_DIP) && dst_ip.a.ipv4_addr)
		spec->hdr.dst_addr = dst_ip.a.ipv4_addr;
	return 0;
}

static void doca_gw_dpdk_build_ipv4_flow_item(struct doca_dpdk_item_entry *entry,
						struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *flow_item = entry->item;
	struct doca_ip_addr src_ip = DOCA_GET_SRC_IP(match, type);
	struct doca_ip_addr dst_ip = DOCA_GET_DST_IP(match, type);
	struct rte_flow_item_ipv4 *spec = &entry->item_data.ipv4.spec;
	struct rte_flow_item_ipv4 *mask = &entry->item_data.ipv4.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	entry->item_data.ipv4.match_layer = type;//inner or outer
	if (!doca_is_ip_zero(&src_ip)){
		spec->hdr.src_addr = src_ip.a.ipv4_addr;
		mask->hdr.src_addr = UINT32_MAX;
		if (doca_is_ip_max(&src_ip))
			entry->flags |= DOCA_MODIFY_SIP;
	}
	if (!doca_is_ip_zero(&dst_ip)){
		spec->hdr.dst_addr = dst_ip.a.ipv4_addr;
		mask->hdr.dst_addr = UINT32_MAX;
		if (doca_is_ip_max(&dst_ip))
			entry->flags |= DOCA_MODIFY_DIP;
	}
	spec->hdr.next_proto_id = (type == OUTER_MATCH)?
                                  match->out_l4_type:match->in_l4_type;
	mask->hdr.next_proto_id = UINT8_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_ipv4_item;
}

/**
 * @brief todo.
 *    
 * @entry match
 *
 * @return 
 */
static int doca_gw_dpdk_modify_ipv6_item(__rte_unused struct doca_dpdk_item_entry *entry, __rte_unused struct doca_gw_match *match)
{
	return 0;
}

static void doca_gw_dpdk_build_ipv6_flow_item(struct doca_dpdk_item_entry *entry, 
			struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *item = entry->item;
	struct doca_ip_addr src_ip = DOCA_GET_SRC_IP(match, type);
	struct doca_ip_addr dst_ip = DOCA_GET_DST_IP(match, type);
	struct rte_flow_item_ipv6 *spec = &entry->item_data.ipv6.spec;
	struct rte_flow_item_ipv6 *mask = &entry->item_data.ipv6.mask;

	item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	if (!doca_is_ip_zero(&src_ip)){
		doca_set_item_ipv6_max(mask->hdr.src_addr);
		memcpy(spec->hdr.src_addr, src_ip.a.ipv6_addr, sizeof(src_ip.a.ipv6_addr));
		if (doca_is_ip_max(&src_ip))
			entry->flags |= DOCA_MODIFY_SIP;
	}
	if (!doca_is_ip_zero(&dst_ip)){
		doca_set_item_ipv6_max(mask->hdr.dst_addr);
		memcpy(spec->hdr.dst_addr, dst_ip.a.ipv6_addr, sizeof(dst_ip.a.ipv6_addr));
		if (doca_is_ip_max(&dst_ip))
			entry->flags |= DOCA_MODIFY_DIP;
	}
	spec->hdr.proto = match->out_l4_type;
	mask->hdr.proto = UINT8_MAX;
	item->spec = spec;
	item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_ipv6_item;
}

static int
doca_gw_dpdk_modify_vxlan_item(struct doca_dpdk_item_entry *entry,
						struct doca_gw_match *match)
{
	struct rte_flow_item_vxlan *spec = &entry->item_data.vxlan.spec;

	if (match->tun.vxlan.tun_id) 
		memcpy(spec->vni, (uint8_t*)(&match->tun.vxlan.tun_id), 3);
	return 0;
}

static void doca_gw_dpdk_build_vxlan_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_vxlan *spec = &entry->item_data.vxlan.spec;
	struct rte_flow_item_vxlan *mask = &entry->item_data.vxlan.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_VXLAN;
	if (!match->tun.vxlan.tun_id) 
		return;
	doca_set_item_vni_max(mask->vni);
	memcpy(spec->vni, (uint8_t*)(&match->tun.vxlan.tun_id), 3); //TODO
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (match->tun.vxlan.tun_id == UINT32_MAX) {
		entry->flags |= DOCA_MODIFY_VXLAN_VNI;
		entry->modify_item = doca_gw_dpdk_modify_vxlan_item;
	}
}

static void doca_gw_dpdk_build_gre_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_gre *spec = &entry->item_data.gre.spec;

	flow_item->type = RTE_FLOW_ITEM_TYPE_GRE;
	spec->protocol = doca_gw_get_l3_protol(match, INNER_MATCH);
}

static int
doca_gw_dpdk_modify_gre_key_item(struct doca_dpdk_item_entry *entry,
						struct doca_gw_match *match)
{
	uint32_t *spec = &entry->item_data.gre_key.spec;

	if (match->tun.gre.key)
		*spec = match->tun.gre.key;
	return 0;
}

static void doca_gw_dpdk_build_gre_key_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	uint32_t *spec = &entry->item_data.gre_key.spec;
	uint32_t *mask = &entry->item_data.gre_key.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_GRE_KEY;
	if (!match->tun.gre.key)
		return;
	*spec = match->tun.gre.key;
	*mask = UINT32_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (match->tun.gre.key == UINT32_MAX) {
		entry->flags |= DOCA_MODIFY_GRE_KEY;
		entry->modify_item = doca_gw_dpdk_modify_gre_key_item;
	}
}

static void doca_gw_dpdk_build_inner_eth_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_eth *spec = &entry->item_data.eth.spec;
	struct rte_flow_item_eth *mask = &entry->item_data.eth.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_ETH;
	spec->type = doca_gw_get_l3_protol(match, OUTER_MATCH);
	mask->type = UINT16_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
}

static void doca_gw_dpdk_build_end_flow_item(struct doca_dpdk_item_entry *entry)
{
	struct rte_flow_item *flow_item = entry->item;
	flow_item->type = RTE_FLOW_ITEM_TYPE_END;
}

static int
doca_gw_dpdk_modify_tcp_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	uint8_t layer = entry->item_data.tcp.match_layer;
	rte_be16_t src_port = DOCA_GET_SPORT(match, layer);
	rte_be16_t dst_port = DOCA_GET_DPORT(match, layer);
	struct rte_flow_item_tcp *spec = &entry->item_data.tcp.spec;

	if ((entry->flags & DOCA_MODIFY_SPORT) && src_port)
		spec->hdr.src_port = src_port;
	if ((entry->flags & DOCA_MODIFY_DPORT) && dst_port)
		spec->hdr.dst_port = dst_port;
	return 0;
}

static void doca_gw_dpdk_build_tcp_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *item = entry->item;
	rte_be16_t src_port = DOCA_GET_SPORT(match, type);
	rte_be16_t dst_port = DOCA_GET_DPORT(match, type);
	struct rte_flow_item_tcp *spec = &entry->item_data.tcp.spec;
	struct rte_flow_item_tcp *mask = &entry->item_data.tcp.mask;

	entry->item_data.tcp.match_layer = type;
	item->type = RTE_FLOW_ITEM_TYPE_TCP;
	if (src_port) {
		spec->hdr.src_port = src_port;
		mask->hdr.src_port = UINT16_MAX;
		if (src_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_SPORT;
	}
	if (dst_port) {
		spec->hdr.dst_port = dst_port;
		mask->hdr.dst_port = UINT16_MAX;
		if (dst_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_DPORT;
	}
	if (src_port == 0 && dst_port == 0)
		return;
	item->spec = spec;
	item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_tcp_flow_item;
}

static int
doca_gw_dpdk_modify_udp_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	uint8_t layer = entry->item_data.udp.match_layer;
	rte_be16_t src_port = DOCA_GET_SPORT(match, layer);
	rte_be16_t dst_port = DOCA_GET_DPORT(match, layer);
	struct rte_flow_item_udp *spec = (struct rte_flow_item_udp *)((uintptr_t)entry->item->spec);

	if ((entry->flags & DOCA_MODIFY_SPORT) && src_port)
		spec->hdr.src_port = src_port;
	if ((entry->flags & DOCA_MODIFY_DPORT) && dst_port)
		spec->hdr.dst_port = dst_port;
	return 0;
}

static void doca_gw_dpdk_build_udp_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *item = entry->item;
	rte_be16_t src_port = DOCA_GET_SPORT(match, type);
	rte_be16_t dst_port = DOCA_GET_DPORT(match, type);
	struct rte_flow_item_udp *spec = &entry->item_data.udp.spec;
	struct rte_flow_item_udp *mask = &entry->item_data.udp.mask;

	entry->item_data.udp.match_layer = type;
	item->type = RTE_FLOW_ITEM_TYPE_UDP;
	if (src_port) {
		spec->hdr.src_port = src_port;
		mask->hdr.src_port = UINT16_MAX;
		if (src_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_SPORT;
	}
	if (dst_port) {
		spec->hdr.dst_port = dst_port;
		mask->hdr.dst_port = UINT16_MAX;
		if (dst_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_DPORT;
	}
	if (src_port == 0 && dst_port == 0)
		return;
	item->spec = spec;
	item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_udp_flow_item;
	return;
}

static int doca_gw_dpdk_build_item(struct doca_gw_match *match,
					struct doca_gw_pipe_dpdk_flow *pipe_flow, struct doca_gw_error *err)
{
#define NEXT_ITEM (&pipe_flow->item_entry[idx++]) //reduce line length
	uint8_t idx = 0, type = OUTER_MATCH;

	doca_gw_dpdk_build_eth_flow_item(NEXT_ITEM, match);
	if (match->vlan_id)
		doca_gw_dpdk_build_vlan_item(NEXT_ITEM, match);
	if (doca_match_is_ipv4(match, type))
		doca_gw_dpdk_build_ipv4_flow_item(NEXT_ITEM, match, type);
	else
		doca_gw_dpdk_build_ipv6_flow_item(NEXT_ITEM, match, type);
	if((match->tun.type != DOCA_TUN_NONE)) {
		switch (match->tun.type) {
		case DOCA_TUN_VXLAN:
			if (!match->out_dst_port)
				match->out_dst_port = DOCA_VXLAN_DEFAULT_PORT;
			doca_gw_dpdk_build_udp_flow_item(NEXT_ITEM, match, type);
			doca_gw_dpdk_build_vxlan_flow_item(NEXT_ITEM, match);
			doca_gw_dpdk_build_inner_eth_flow_item(NEXT_ITEM, match);
			break;
		case DOCA_TUN_GRE:
			doca_gw_dpdk_build_gre_flow_item(NEXT_ITEM, match);
			doca_gw_dpdk_build_gre_key_flow_item(NEXT_ITEM, match);
			break;
		default:
			err->type = DOCA_ERROR_UNSUPPORTED;
			DOCA_LOG_INFO("not support type:%x\n", match->tun.type);
			return -1;
		}
		type = INNER_MATCH;
		if (doca_match_is_ipv4(match, type))
			doca_gw_dpdk_build_ipv4_flow_item(NEXT_ITEM, match, type);
		else
			doca_gw_dpdk_build_ipv6_flow_item(NEXT_ITEM, match, type);
	}
	if (doca_match_is_tcp(match))
		doca_gw_dpdk_build_tcp_flow_item(NEXT_ITEM, match, type);
	else if (doca_match_is_udp(match))
		doca_gw_dpdk_build_udp_flow_item(NEXT_ITEM, match, type);
	else {
		DOCA_LOG_INFO("not support l3 type.\n");
		return -1;
	}
	doca_gw_dpdk_build_end_flow_item(NEXT_ITEM);
	pipe_flow->nb_items = idx;
	return 0;
}

/*
  *currently, only for decap, only need the decap length
  *for encap, will check how to implement.
  	is encap buffer fixed or will be modifid by packet info?
*/
static void
doca_gw_dpdk_build_ether_header(uint8_t **header, struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_ether_hdr eth_hdr;
	struct doca_gw_match *match = cfg->match;

	memset(&eth_hdr, 0, sizeof(struct rte_ether_hdr));
	if (!doca_is_mac_zero(match->out_dst_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &eth_hdr.s_addr);
	if (!doca_is_mac_zero(match->out_src_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &eth_hdr.d_addr);
	eth_hdr.ether_type = doca_gw_get_l3_protol(match, OUTER_MATCH);
	memcpy(*header, &eth_hdr, sizeof(eth_hdr));
	*header += sizeof(eth_hdr);
	if (match->vlan_id) {
		struct rte_vlan_hdr vlan;
		memset(&vlan, 0x0, sizeof(vlan));
		memcpy(*header, &vlan, sizeof(vlan));
		*header += sizeof(vlan);
	}
}

static void
doca_gw_dpdk_build_ipv4_header(uint8_t **header,
			__rte_unused struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_ipv4_hdr ipv4_hdr;

	memset(&ipv4_hdr, 0, sizeof(struct rte_ipv4_hdr));
	if (!doca_is_ip_zero(&cfg->match->out_src_ip))
		ipv4_hdr.src_addr = cfg->match->out_src_ip.a.ipv4_addr;
	if (!doca_is_ip_zero(&cfg->match->out_dst_ip))
		ipv4_hdr.dst_addr = cfg->match->out_dst_ip.a.ipv4_addr;
	if (!cfg->match->out_l4_type)
		ipv4_hdr.next_proto_id = cfg->match->out_l4_type;
	memcpy(*header, &ipv4_hdr, sizeof(ipv4_hdr));
	*header += sizeof(ipv4_hdr); //todo, need check if has optional fields in iphdr
}

static void
doca_gw_dpdk_build_udp_header(uint8_t **header, struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_udp_hdr udp_hdr;

	memset(&udp_hdr, 0, sizeof(struct rte_flow_item_udp));
	if (cfg->match->out_src_port)
		udp_hdr.src_port = cfg->match->out_src_port;
	if (cfg->match->out_dst_port)
		udp_hdr.dst_port = cfg->match->out_dst_port;
	memcpy(*header, &udp_hdr, sizeof(udp_hdr));
	*header += sizeof(udp_hdr);
}

static void
doca_gw_dpdk_build_vxlan_header(uint8_t **header,
		struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_vxlan_hdr vxlan_hdr;

	memset(&vxlan_hdr, 0, sizeof(struct rte_vxlan_hdr));
	memcpy(&vxlan_hdr.vx_vni, (uint8_t*)(&cfg->match->tun.vxlan.tun_id), 3);
	memcpy(*header, &vxlan_hdr, sizeof(vxlan_hdr));
	*header += sizeof(vxlan_hdr);
}

static void
doca_gw_dpdk_build_gre_header(uint8_t **header,
		struct doca_gw_pipeline_cfg *cfg)
{
	uint32_t *key_data;
	struct rte_gre_hdr gre_hdr;

	memset(&gre_hdr, 0, sizeof(struct rte_gre_hdr));
	gre_hdr.k = 1;
	gre_hdr.proto = doca_gw_get_l3_protol(cfg->match, INNER_MATCH);
	memcpy(*header, &gre_hdr, sizeof(gre_hdr));
	*header += sizeof(gre_hdr);
	key_data = (uint32_t *)(*header);
	*key_data = cfg->match->tun.gre.key;
	*header += sizeof(uint32_t);
}

struct endecap_layer doca_endecap_layers[] = {
	{FILL_ETH_HDR,		doca_gw_dpdk_build_ether_header},
	{FILL_IPV4_HDR,		doca_gw_dpdk_build_ipv4_header},
	{FILL_UDP_HDR,		doca_gw_dpdk_build_udp_header},
	{FILL_VXLAN_HDR,	doca_gw_dpdk_build_vxlan_header},
	{FILL_GRE_HDR,		doca_gw_dpdk_build_gre_header},	
};

static void
doca_gw_dpdk_build_endecap_data(uint8_t **header,
			struct doca_gw_pipeline_cfg *cfg,
			uint16_t flags)
{
	uint8_t idx;
	struct endecap_layer *layer;
	
	for (idx = 0; idx < RTE_DIM(doca_endecap_layers); idx++) {
		layer = &doca_endecap_layers[idx];
		if (flags & layer->layer)
			layer->fill_data(header, cfg);
	}
}

static void doca_gw_dpdk_build_decap_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t decap_layer)
{
	uint8_t *header;
	struct rte_flow_action *action = entry->action;
	struct doca_dpdk_action_rawdecap_data *decap;

	decap = &entry->action_data.rawdecap;
	header = decap->data;
	doca_gw_dpdk_build_endecap_data(&header, cfg, decap_layer);
	decap->conf.data = decap->data;
	decap->conf.size = header - decap->data;
	action->type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	action->conf = &decap->conf;
}

static int doca_gw_dpdk_build_tunnel_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg)
{
	uint8_t layer;
	struct doca_gw_match *match = cfg->match;

	switch (match->tun.type) {
		case DOCA_TUN_VXLAN:
			layer = FILL_ETH_HDR | FILL_IPV4_HDR | FILL_UDP_HDR | FILL_VXLAN_HDR;
			doca_gw_dpdk_build_decap_action(entry, cfg, layer);
			return 0;
		case DOCA_TUN_GRE:
			layer = FILL_ETH_HDR | FILL_IPV4_HDR | FILL_GRE_HDR;
			doca_gw_dpdk_build_decap_action(entry, cfg, layer);
			return 0;	
		default:
			return -1;
	}
}

static int doca_gw_dpdk_modify_mac_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_actions *pkt_action)
{
	uint8_t *mac_addr;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_mac *set_mac = &entry->action_data.mac.set_mac;

	mac_addr = action->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC?
		pkt_action->mod_src_mac : pkt_action->mod_dst_mac;
	if (!doca_is_mac_zero(mac_addr))
		memcpy(set_mac->mac_addr, mac_addr, DOCA_ETHER_ADDR_LEN);
	return 0;
}

static void doca_gw_dpdk_build_mac_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t type)
{
	struct rte_flow_action *action = entry->action;
	uint8_t *mac_addr;
	struct rte_flow_action_set_mac *set_mac = &entry->action_data.mac.set_mac;

	mac_addr = (type == DOCA_SRC? cfg->actions->mod_src_mac : cfg->actions->mod_dst_mac);
	memcpy(set_mac->mac_addr, mac_addr, DOCA_ETHER_ADDR_LEN);
	action->conf = set_mac;
	action->type = (type == DOCA_SRC? RTE_FLOW_ACTION_TYPE_SET_MAC_SRC : RTE_FLOW_ACTION_TYPE_SET_MAC_DST);
	if (doca_is_mac_max(mac_addr))
		entry->modify_action = doca_gw_dpdk_modify_mac_action;
}

static int doca_gw_dpdk_modify_ipv4_addr_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_actions *pkt_action)
{
	struct doca_ip_addr *ip_addr;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_ipv4 *ipv4 = &entry->action_data.ipv4.ipv4;

	ip_addr = action->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC?
		&pkt_action->mod_src_ip : &pkt_action->mod_dst_ip;
	if (!doca_is_ip_zero(ip_addr))
		ipv4->ipv4_addr = ip_addr->a.ipv4_addr;
	return 0;
}

static void doca_gw_dpdk_build_ipv4_addr_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t type)
{
	struct rte_flow_action *action = entry->action;
	struct doca_ip_addr *ip_addr;
	struct rte_flow_action_set_ipv4 *ipv4 = &entry->action_data.ipv4.ipv4;

	ip_addr = (type == DOCA_SRC? &cfg->actions->mod_src_ip : &cfg->actions->mod_dst_ip);
	ipv4->ipv4_addr = ip_addr->a.ipv4_addr;
	action->type = (type == DOCA_SRC? RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC : RTE_FLOW_ACTION_TYPE_SET_IPV4_DST);
	action->conf = ipv4;
	if (doca_is_ip_max(ip_addr))
		entry->modify_action = doca_gw_dpdk_modify_ipv4_addr_action;
}

static int doca_gw_dpdk_modify_l4_port_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_actions *pkt_action)
{
	uint16_t l4port;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_tp *set_tp = &entry->action_data.l4port.l4port;

	l4port = action->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC?
		pkt_action->mod_src_port : pkt_action->mod_dst_port;
	if (l4port)
		set_tp->port = l4port;
	return 0;
}

static void doca_gw_dpdk_build_l4_port_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t type)
{
	uint16_t l4port;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_tp *set_tp = &entry->action_data.l4port.l4port;

	l4port = (type == DOCA_SRC? cfg->actions->mod_src_port : cfg->actions->mod_dst_port);
	set_tp->port = l4port;
	action->type = (type == DOCA_SRC? RTE_FLOW_ACTION_TYPE_SET_TP_SRC : RTE_FLOW_ACTION_TYPE_SET_TP_DST);
	action->conf = set_tp;
	if (l4port == UINT16_MAX)
		entry->modify_action = doca_gw_dpdk_modify_l4_port_action;
}

static void doca_gw_dpdk_build_dec_ttl_action(struct doca_dpdk_action_entry *entry)
{
	struct rte_flow_action *action = entry->action;

	action->type = RTE_FLOW_ACTION_TYPE_DEC_TTL;
	action->conf = NULL;
}

static int doca_gw_dpdk_build_action(struct doca_gw_pipeline_cfg *cfg,
					struct doca_gw_pipe_dpdk_flow *pipe_flow)
{
#define NEXT_ACTION (&pipe_flow->action_entry[idx++])
	int ret = 0;
	uint8_t idx = 0;
	struct doca_gw_match *match = cfg->match;
	struct doca_gw_actions *actions = cfg->actions;

	if (actions->decap && match->tun.type)
		ret = doca_gw_dpdk_build_tunnel_action(NEXT_ACTION, cfg);
	if (!doca_is_mac_zero(actions->mod_src_mac))
		doca_gw_dpdk_build_mac_action(NEXT_ACTION, cfg, DOCA_SRC);
	if (!doca_is_mac_zero(actions->mod_dst_mac))
		doca_gw_dpdk_build_mac_action(NEXT_ACTION, cfg, DOCA_DST);
	if (!doca_is_ip_zero(&actions->mod_src_ip))
		doca_gw_dpdk_build_ipv4_addr_action(NEXT_ACTION, cfg, DOCA_SRC);
	if (!doca_is_ip_zero(&actions->mod_dst_ip))
		doca_gw_dpdk_build_ipv4_addr_action(NEXT_ACTION, cfg, DOCA_DST);
	if (actions->mod_src_port)
		doca_gw_dpdk_build_l4_port_action(NEXT_ACTION, cfg, DOCA_SRC);
	if (actions->mod_dst_port)
		doca_gw_dpdk_build_l4_port_action(NEXT_ACTION, cfg, DOCA_DST);
	if (actions->dec_ttl)
		doca_gw_dpdk_build_dec_ttl_action(NEXT_ACTION);
	pipe_flow->nb_actions_pipe = idx;
	return ret;
}

static void doca_gw_dpdk_build_end_action(struct doca_gw_pipe_dpdk_flow *pipe)
{
	struct rte_flow_action *action = &pipe->actions[pipe->nb_actions_entry++];
	action->type = RTE_FLOW_ACTION_TYPE_END;
}

static inline uint64_t
doca_gw_get_rss_type(uint32_t rss_type)
{
	uint64_t rss_flags = 0;
	if (rss_type && DOCA_RSS_IP)
		rss_flags |= ETH_RSS_IP;
	if (rss_type && DOCA_RSS_UDP)
		rss_flags |= ETH_RSS_UDP;
	if (rss_type && DOCA_RSS_TCP)
		rss_flags |= ETH_RSS_TCP;
	return rss_flags;
}

static int 
doca_gw_dpdk_build_rss_action(struct doca_dpdk_action_entry *entry,
									struct doca_fwd_table_cfg *fwd_cfg)
{
	int qidx;
	struct rte_flow_action *action = entry->action;
	struct doca_dpdk_action_rss_data *rss = &entry->action_data.rss;

	rss->conf.queue_num = fwd_cfg->rss.num_queues;
	for (qidx = 0; qidx < fwd_cfg->rss.num_queues; qidx++)
		rss->queue[qidx] = fwd_cfg->rss.queues[qidx];
	rss->conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	rss->conf.types = doca_gw_get_rss_type(fwd_cfg->rss.rss_flags);
	rss->conf.queue = rss->queue;
	action->type = RTE_FLOW_ACTION_TYPE_RSS;
	action->conf = &rss->conf;
	return 0;
}

static int doca_gw_dpdk_build_fwd(struct doca_gw_pipe_dpdk_flow *pipe,
									struct doca_fwd_table_cfg *fwd_cfg)
{
	struct doca_dpdk_action_entry *action_entry;

	action_entry = &pipe->action_entry[pipe->nb_actions_entry++];
	switch(fwd_cfg->type) {
		case DOCA_FWD_RSS:
			doca_gw_dpdk_build_rss_action(action_entry, fwd_cfg);
			break;
		default:
			return 1;
	}
	return 0;
}

static int
doca_gw_dpdk_create_meter_profile(uint16_t port_id, uint32_t id, struct doca_gw_monitor *mon)
{
	int ret;
	struct rte_mtr_error error;
	struct rte_mtr_meter_profile mp;

	memset(&mp, 0, sizeof(struct rte_mtr_meter_profile));
	mp.alg = RTE_MTR_SRTCM_RFC2697;
	mp.srtcm_rfc2697.cir = mon->m.cir;
	mp.srtcm_rfc2697.cbs = mon->m.cbs;
	mp.srtcm_rfc2697.ebs = 0;

	ret = rte_mtr_meter_profile_add(port_id, id, &mp, &error);
	if (ret != 0) {
		DOCA_LOG_ERR("Port %u create Profile id %u error(%d) message: %s\n",
			port_id, id, error.type,
			error.message ? error.message : "(no stated reason)");
		return -1;
	}
	return 0;
}

static int
doca_gw_dpdk_create_meter_policy(uint16_t port_id, uint32_t policy_id,
						struct doca_fwd_table_cfg *fwd_cfg)
{
	int ret;
	struct rte_mtr_error error;
	struct rte_flow_action_rss conf;
	struct rte_flow_action g_actions[2], r_actions[2];
	const struct rte_flow_action *actions[RTE_COLORS];

	if (fwd_cfg->type != DOCA_FWD_RSS) {
		DOCA_LOG_ERR("unsupport fwd type:%d\n", fwd_cfg->type);
		return -1;
	}
	memset(&conf, 0x0, sizeof(conf));
	conf.queue_num = fwd_cfg->rss.num_queues;
	conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	conf.types = doca_gw_get_rss_type(fwd_cfg->rss.rss_flags);
	conf.queue = fwd_cfg->rss.queues;
	g_actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	g_actions[0].conf = &conf;
	g_actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	g_actions[1].conf = NULL;

	r_actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
	r_actions[0].conf = NULL;
	r_actions[1].type = RTE_FLOW_ACTION_TYPE_END;
	r_actions[1].conf = NULL;

	actions[0] = &g_actions[0];
	actions[1] = NULL;
	actions[2] = &r_actions[0];

	ret = rte_mtr_meter_policy_create(port_id, policy_id, actions, &error);
	if (ret) {
		printf("meter add failed port_id  %d\n", port_id);
		return -1;
	}
	return 0;
}

static int
doca_gw_dpdk_create_meter_rule(int port_id, uint32_t meter_id,
					struct doca_gw_pipelne_entry *pipe_entry)
{
	int ret;
	struct rte_mtr_params params;
	struct rte_mtr_error error;

	memset(&params, 0, sizeof(struct rte_mtr_params));
	params.meter_enable = 1;
	params.stats_mask = 0xffff;
	params.use_prev_mtr_color = 0;
	params.dscp_table = NULL;

	/*create meter*/
	params.meter_profile_id = pipe_entry->meter_profile_id;
	params.meter_policy_id = pipe_entry->meter_policy_id;

	ret = rte_mtr_create(port_id, meter_id, &params, 0, &error);
	if (ret != 0) {
		DOCA_LOG_ERR("Port %u create meter idx(%d) error(%d) message: %s\n",
			port_id, meter_id, error.type,
			error.message ? error.message : "(no stated reason)");
		return 0;
	}
	return meter_id++;
}

static int 
doca_gw_dpdk_build_meter_action(struct doca_gw_pipelne_entry *pipe_entry,
							uint16_t port_id,
							struct doca_dpdk_action_entry *entry, 
							struct doca_gw_monitor *mon,
							struct doca_fwd_table_cfg *cfg)
{
	int ret;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_meter *meter_conf;
	struct doca_dpdk_action_meter_data *meter_data;
	//uint32_t id = doca_id_pool_alloc_id(doca_gw_engine.meter_pool);  1 - 4096 
	static uint32_t id = 0;

	id++;
	if (id <= 0) {
		//TODO should be better handled
		DOCA_LOG_ERR("out of meter profile ids");
		return 0;
	}

	meter_data = &entry->action_data.meter;
	ret = doca_gw_dpdk_create_meter_profile(port_id, id, mon);
	if (ret < 0)
		return -1;
	ret = doca_gw_dpdk_create_meter_policy(port_id, id, cfg);
	if (ret < 0)
		return -1;
	meter_data->policy_id = id;
	meter_data->prof_id = id;
	pipe_entry->meter_profile_id = meter_data->prof_id;
	pipe_entry->meter_policy_id = meter_data->policy_id;
	meter_conf = &meter_data->conf;
	ret = doca_gw_dpdk_create_meter_rule(port_id, id, pipe_entry);
	if (ret < 0)
		return -1;
	pipe_entry->meter_id = id;
	meter_conf->mtr_id = id;
	action->type = RTE_FLOW_ACTION_TYPE_METER;
	action->conf = meter_conf;
	return 0;
}

static int
doca_gw_dpdk_build_monitor_action(struct doca_gw_pipelne_entry *pipe_entry,
						struct doca_gw_pipe_dpdk_flow *pipe, 
						struct doca_gw_monitor *mon,
						struct doca_fwd_table_cfg *cfg)
{
	uint16_t port_id = pipe->port_id;
	struct doca_dpdk_action_entry *entry;

	if (mon->flags & DOCA_GW_METER) {
		entry = &pipe->action_entry[pipe->nb_actions_entry++];
		if (doca_gw_dpdk_build_meter_action(pipe_entry, port_id, entry, mon, cfg))
			return -1;
	}
	//todo:  count/aging...
	return 0;
}

static int
doca_gw_dpdk_modify_pipe_match(struct doca_gw_pipe_dpdk_flow *pipe,
	struct doca_gw_match *match)
{
	int idex, ret;
	struct doca_dpdk_item_entry *item_entry;

	for (idex = 0 ; idex < pipe->nb_items; idex++) {
		item_entry = &pipe->item_entry[idex];
		if (item_entry->modify_item == NULL)
			continue;
		ret = item_entry->modify_item(item_entry, match);
		if (ret)
			return ret;
	}
	return 0;
}

static int
doca_gw_dpdk_modify_pipe_actions(struct doca_gw_pipe_dpdk_flow *pipe,
	struct doca_gw_actions *actions)
{
	int idex, ret;
	struct doca_dpdk_action_entry *action_entry;
	
	for (idex = 0 ; idex < pipe->nb_actions_entry; idex++) {
		action_entry = &pipe->action_entry[idex];
		if (action_entry->modify_action == NULL)
			continue;
		ret = action_entry->modify_action(action_entry, actions);
		if (ret)
			return ret;
	}
	return 0;
}

static struct rte_flow*
doca_gw_dpdk_create_flow(uint16_t port_id,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[])
{
	struct rte_flow *flow;
	struct rte_flow_error err;

	doca_dump_rte_flow("create rte flow:", port_id, attr,
		pattern, actions);
	flow = rte_flow_create(port_id, attr, pattern, actions, &err);
	if (!flow) {
		DOCA_LOG_ERR("Port %u create flow fail, type %d message: %s\n",
			port_id, err.type,
			err.message ? err.message : "(no stated reason)");
	}
	return flow;
}

//create flow gourp 0 match eth action jump group 1
static struct rte_flow*
doca_gw_dpdk_create_root_jump(uint16_t port_id)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS];
	struct rte_flow_action actions[MAX_ACTIONS];
	struct rte_flow_action_jump jump;

	memset(&attr, 0x0, sizeof(struct rte_flow_attr));
	memset(items, 0x0, sizeof(items));
	memset(actions, 0x0, sizeof(actions));
	attr.group = 0;
	attr.ingress = 1;
	items[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[0].type = RTE_FLOW_ITEM_TYPE_END;
	jump.group = 1;
	actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
	actions[0].conf = &jump;
	return doca_gw_dpdk_create_flow(port_id, &attr, items, actions);
}

/*default match, -> queue[0]*/
static struct rte_flow*
doca_gw_dpdk_create_def_rss(uint16_t port_id)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS];
	struct rte_flow_action actions[MAX_ACTIONS];
	struct doca_dpdk_action_rss_data rss;

	memset(&attr, 0x0, sizeof(struct rte_flow_attr));
	memset(items, 0x0, sizeof(items));
	memset(actions, 0x0, sizeof(actions));	
	attr.group = 1;
	attr.ingress = 1;
	attr.priority = MAX_FLOW_FRIO;
	items[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[1].type = RTE_FLOW_ITEM_TYPE_END;

	memset(&rss, 0x0, sizeof(rss));
	rss.queue[0] = 0;
	rss.conf.queue_num = 1;
	rss.conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	rss.conf.types = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
	rss.conf.queue = rss.queue;
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &rss.conf;
	return doca_gw_dpdk_create_flow(port_id, &attr, items, actions);
}


static struct rte_flow *
doca_gw_dpdk_pipe_create_entry_flow(struct doca_gw_pipelne_entry *entry, struct doca_gw_pipe_dpdk_flow *pipe,
					struct doca_gw_match *match, struct doca_gw_actions *actions,
					struct doca_gw_monitor *mon, struct doca_fwd_table_cfg *cfg,
					__rte_unused struct doca_gw_error *err)
{
	DOCA_LOG_DBG("pip create new flow:\n");
	doca_dump_gw_match(match);
	doca_dump_gw_actions(actions);
	pipe->nb_actions_entry = pipe->nb_actions_pipe;
	if(match == NULL && actions == NULL && cfg == NULL)
		return NULL;
	if (doca_gw_dpdk_modify_pipe_match(pipe, match)) {
		DOCA_LOG_ERR("modify pipe match item fail.\n");
		return NULL;
	}
	if (doca_gw_dpdk_modify_pipe_actions(pipe, actions)) {
		DOCA_LOG_ERR("modify pipe action fail.\n");
		return NULL;
	}
	if (mon->flags != DOCA_GW_NONE
		&& doca_gw_dpdk_build_monitor_action(entry, pipe, mon)) {
		DOCA_LOG_ERR("create monitor action fail.\n");
		return NULL;
	}
	if (!(mon->flags & DOCA_GW_METER) && doca_gw_dpdk_build_fwd(pipe, cfg)) {
		DOCA_LOG_ERR("build pipe fwd action fail.");
		return NULL;
	}
	doca_gw_dpdk_build_end_action(pipe);
	return doca_gw_dpdk_create_flow(pipe->port_id, &pipe->attr, pipe->items, pipe->actions);
}

struct doca_gw_pipelne_entry*
doca_gw_dpdk_pipe_create_flow(struct doca_gw_pipeline *pipeline,
					struct doca_gw_match *match, struct doca_gw_actions *actions,
					struct doca_gw_monitor *mon, struct doca_fwd_table_cfg *cfg,
					struct doca_gw_error *err)
{

    struct doca_gw_pipelne_entry *entry;

	entry = (struct doca_gw_pipelne_entry *)malloc(sizeof(struct doca_gw_pipelne_entry));
	if (entry == NULL)
		return NULL;
    entry->pipe_entry = doca_gw_dpdk_pipe_create_entry_flow(entry, &pipeline->flow,
		match, actions, mon, cfg, err);
    if (entry->pipe_entry == NULL) {
		DOCA_LOG_INFO("create pip entry fail,idex:%d", pipeline->pipe_entry_id);
		goto free_pipe_entry;
    }
    entry->id = pipeline->pipe_entry_id++;
	rte_spinlock_lock(&pipeline->entry_lock);
	pipeline->nb_pipe_entrys++;
	LIST_INSERT_HEAD(&pipeline->entry_list, entry, next);
	rte_spinlock_unlock(&pipeline->entry_lock);
	DOCA_LOG_DBG("offload[%d]: pipeline=%p, match =%pi mod %p",
	entry->id, pipeline, match, actions);
	return entry;
free_pipe_entry:
	free(entry);
	return NULL;
}

int doca_gw_dpdk_pipe_free_entry(uint16_t portid, struct doca_gw_pipelne_entry *entry)
{
	int ret;
	struct rte_flow_error flow_err;
	struct rte_mtr_error mtr_err;

	ret = rte_flow_destroy(portid, (struct rte_flow *)entry->pipe_entry, &flow_err);
	if (ret) {
		DOCA_LOG_ERR("Port %u free flow fail, type %d message: %s",
			portid, flow_err.type, flow_err.message ? flow_err.message : "(no stated reason)");
		return -1;
	}
	if (entry->meter_id) {
		ret = rte_mtr_destroy(portid, entry->meter_id, &mtr_err);
		if (ret) {
			DOCA_LOG_ERR("Port %u free meter rule id %u err, type %d message: %s",
				portid, entry->meter_id, mtr_err.type,
				mtr_err.message ? mtr_err.message : "(no stated reason)");
			return -1;
		}
	}	
	if (entry->meter_policy_id) {
		ret = rte_mtr_meter_policy_delete(portid, entry->meter_policy_id, &mtr_err);
		if (ret) {
			DOCA_LOG_ERR("Port %u free meter policy id %u err, type %d message: %s",
				portid, entry->meter_policy_id, mtr_err.type,
				mtr_err.message ? mtr_err.message : "(no stated reason)");
			return -1;
		}
	}
	if (entry->meter_profile_id) {
		ret = rte_mtr_meter_profile_delete(portid, entry->meter_profile_id, &mtr_err);
		if (ret) {
			DOCA_LOG_ERR("Port %u free meter profile id %u err, type %d message: %s",
				portid, entry->meter_profile_id, mtr_err.type,
				mtr_err.message ? mtr_err.message : "(no stated reason)");
			return -1;
		}
	}
	return 0;
}
/*todo , how to manager root/queue flows for one port.*/
int
doca_gw_dpdk_init_port(uint16_t port_id)
{
	struct rte_flow *root,*queue;

	root = doca_gw_dpdk_create_root_jump(port_id);
	if(root == NULL)
		return -1;
	queue = doca_gw_dpdk_create_def_rss(port_id);
	if(queue == NULL)
		return -1;
	return 0;
}

/**
 * @brief: there is not create the pipeline flows templet?
 *    
 * @param match
 *
 * @return 
 */
static int
doca_gw_dpdk_create_pipe_flow(struct doca_gw_pipe_dpdk_flow *flow, 
							struct doca_gw_pipeline_cfg *cfg,
							struct doca_gw_error *err)
{
	int ret;

	flow->port_id = (uint16_t)cfg->port->port_id;
	flow->attr.ingress = 1;
	flow->attr.group = 1; // group 0 jump group 1
	ret = doca_gw_dpdk_build_item(cfg->match, flow, err);
	if (ret) {
		err->type = DOCA_ERROR_PIPE_BUILD_IMTE_ERROR;
		return -1;
	}
	ret = doca_gw_dpdk_build_action(cfg, flow);
	if (ret) {
		err->type = DOCA_ERROR_PIPE_BUILD_ACTION_ERROR;
		return -1;
	}
	doca_dump_rte_flow("create pipe:", flow->port_id, &flow->attr,
		flow->items, flow->actions);
	return 0;
}

struct doca_gw_pipeline*
doca_gw_dpdk_create_pipe(struct doca_gw_pipeline_cfg *cfg, struct doca_gw_error *err)
{
	int ret;
	uint32_t idx;
	static uint32_t pipe_id = 1;
	struct doca_gw_pipeline *pl;
	struct doca_gw_pipe_dpdk_flow *flow;

	DOCA_LOG_DBG("port:%u create pipe:%s\n", cfg->port->port_id, cfg->name);
	doca_dump_gw_match(cfg->match);
	doca_dump_gw_actions(cfg->actions);
	pl = malloc(sizeof(struct doca_gw_pipeline));
	if (pl == NULL)
		return NULL;
	memset(pl,0,sizeof(struct doca_gw_pipeline));
	strcpy(pl->name, cfg->name);
	LIST_INIT(&pl->entry_list);
	rte_spinlock_init(&pl->entry_lock);
	pl->id = pipe_id++;
	flow = &pl->flow;
	for (idx = 0 ; idx < MAX_ITEMS; idx++)
		flow->item_entry[idx].item = &pl->flow.items[idx];
	for (idx = 0 ; idx < MAX_ACTIONS; idx++)
		flow->action_entry[idx].action = &pl->flow.actions[idx];
	ret = doca_gw_dpdk_create_pipe_flow(flow, cfg, err);
	if(ret) {
		free(pl);
		return NULL;
	}
	rte_spinlock_lock(&cfg->port->pipe_lock);
	LIST_INSERT_HEAD(&cfg->port->pipe_list, pl, next);
	rte_spinlock_unlock(&cfg->port->pipe_lock);
    return pl;
}

static struct doca_gw_port *doca_get_port_byid(uint8_t port_id)
{
	return doca_gw_used_ports[port_id];
}

static struct doca_gw_port *doca_alloc_port_byid(uint8_t port_id, struct doca_gw_port_cfg *cfg)
{
	struct doca_gw_port *port;

	port = (struct doca_gw_port *) malloc(sizeof(struct doca_gw_port) + cfg->priv_data_size);
	if (port == NULL)
		return NULL;
	memset(port, 0x0, sizeof(struct doca_gw_port));
	port->port_id = port_id;
	LIST_INIT(&port->pipe_list);
	rte_spinlock_init(&port->pipe_lock);
	return port;
}

static bool doca_gw_save_port(struct doca_gw_port *port)
{
    int i = 0;
    for ( i = 0 ; i < DOCA_GW_MAX_PORTS ; i++) {
        if (doca_gw_used_ports[i] == NULL) {
            doca_gw_used_ports[i] = port;
            port->idx = i;
            return true;
        }
    }
    return false;
}

struct doca_gw_port * doca_gw_dpdk_port_start(struct doca_gw_port_cfg *cfg,
				__rte_unused struct doca_gw_error *err)
{
	struct doca_gw_port *port = doca_alloc_port_byid(cfg->port_id, cfg);

    if ( port == NULL )
        return NULL;
    memset(port, 0, sizeof(struct doca_gw_port));
    if (!doca_gw_save_port(port)) 
        goto fail_port_start;
    return port;
fail_port_start:
	free(port);
	return NULL;
}

static void doca_gw_free_pipe(uint16_t portid, struct doca_gw_pipeline *pipe)
{
	uint32_t nb_pipe_entry = 0;
	struct doca_gw_pipelne_entry *entry;

	DOCA_LOG_INFO("portid:%u free pipeid:%u", portid,pipe->id);
	rte_spinlock_lock(&pipe->entry_lock);
	while((entry = LIST_FIRST(&pipe->entry_list))) {
		LIST_REMOVE(entry, next);
		nb_pipe_entry++;
		doca_gw_dpdk_pipe_free_entry(portid, entry);
		free(entry);		
	}
	rte_spinlock_unlock(&pipe->entry_lock);
	free(pipe);
	DOCA_LOG_INFO("total free pipe entry:%d", nb_pipe_entry);
}

void doca_gw_dpdk_destroy(uint16_t port_id)
{
	struct doca_gw_port *port;
	struct doca_gw_pipeline *pipe;

	port = doca_get_port_byid(port_id);
	if (port)
		return;
	rte_spinlock_lock(&port->pipe_lock);
	while((pipe = LIST_FIRST(&port->pipe_list))) {
		LIST_REMOVE(pipe, next);
		doca_gw_free_pipe(port_id, pipe);
	}
	rte_spinlock_unlock(&port->pipe_lock);
	doca_gw_used_ports[port_id] = NULL;
	free(port);
}

void doca_gw_dpdk_dump_pipeline(uint16_t port_id)
{
	struct doca_gw_port *port;
	struct doca_gw_pipeline *curr;
	static const char *nic_stats_border = "########################";

	printf("\n  %s Pipe line info for port %-2d %s\n",
	       nic_stats_border, port_id, nic_stats_border);
	port = doca_get_port_byid(port_id);
	rte_spinlock_lock(&port->pipe_lock);
	curr = LIST_FIRST(&port->pipe_list);
	while(curr) {
		printf("  pipe line id:%u,name:%s,flow entry count:%u\n",
			curr->id, curr->name, curr->nb_pipe_entrys);
		curr = LIST_NEXT(curr, next);
	}
	rte_spinlock_unlock(&port->pipe_lock);
}

