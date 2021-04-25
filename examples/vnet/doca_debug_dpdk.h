#ifndef _DOCA_DEBUG_DPDK__H_
#define _DOCA_DEBUG_DPDK__H_

enum {
	DEBUG_MBUFF 	= (1 << 0),
	DEBUG_RTE_FLOW	= (1 << 1),
	DEBUG_MATCH 	= (1 << 2),
	DEBUG_ACTIONS 	= (1 << 3),
};

#define MAX_TMP_BUFF 1024

#define doca_log_buff(fmt, args...) \
	sprintf(dump_buff + strlen(dump_buff), fmt , ## args)
#define doca_log_ipv4(item, ipv4_addr) \
	doca_log_buff("%s%d.%d.%d.%d ", item, (ipv4_addr >> 24) & 0xFF, \
		(ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF, ipv4_addr & 0xFF);
#define doca_log_mac(item, eth_addr) \
	doca_log_buff("%s%02X:%02X:%02X:%02X:%02X:%02X ", item, eth_addr[0], \
		eth_addr[1], eth_addr[2], eth_addr[3],	eth_addr[4], eth_addr[5]);

struct dump_hdr {
	uint8_t protocal;
	uint8_t (*dump_hdr)(uint8_t *, uint32_t *);
};

enum {
	DUMP_ETH = 0,
	DUMP_IPV4,
	DUMP_UDP,
	DUMP_TCP,
	DUMP_VXLAN,
	DUMP_GRE,

	DUMP_END,
};

void
doca_dump_rte_flow(const char *name, uint16_t port_id,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item items[],
		const struct rte_flow_action actions[]);
void doca_dump_rte_mbuff(const char *name, struct rte_mbuf *mb);
void doca_dump_gw_match(struct doca_flow_match *match);
void doca_dump_gw_actions(struct doca_flow_actions *actions);


#endif

