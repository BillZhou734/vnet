#include <stdio.h>
#include <rte_vxlan.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_gre.h>
#include "doca_flow.h"
#include "doca_dpdk.h"
#include "doca_log.h"
#include "doca_debug_dpdk.h"

DOCA_LOG_MODULE(doca_debug_dpdk);

static char dump_buff[MAX_TMP_BUFF] = {'\0'}; /*can't parallel dump*/
static char prefix_buff[MAX_TMP_BUFF] = {'\0'};

/*increase dump packet every layer line prefix space*/
static inline void doca_inc_line_prefix(void)
{
	sprintf(prefix_buff + strlen(prefix_buff), "  ");
	doca_log_buff("%s", prefix_buff);
}

static void doca_dump_eth_item(const struct rte_flow_item *item)
{
	const struct rte_flow_item_eth *eth_spec, *eth_mask;

	eth_spec = (const struct rte_flow_item_eth *)item->spec;
	eth_mask = (const struct rte_flow_item_eth *)item->mask;
	doca_log_buff("eth");
	if (eth_spec && !rte_is_zero_ether_addr(&eth_spec->src))
		doca_log_mac(" src spec ", eth_spec->src.addr_bytes);
	if (eth_mask && !rte_is_zero_ether_addr(&eth_mask->src))
		doca_log_mac(" src mask ", eth_mask->src.addr_bytes);
	if (eth_spec && !rte_is_zero_ether_addr(&eth_spec->dst))
		doca_log_mac(" dst spec ", eth_spec->dst.addr_bytes);
	if (eth_mask && !rte_is_zero_ether_addr(&eth_mask->dst))
		doca_log_mac(" dst mask ", eth_mask->dst.addr_bytes);
	if (eth_spec && eth_spec->type)
		doca_log_buff(" type spec 0x%x",
			      rte_be_to_cpu_16(eth_spec->type));
	if (eth_mask && eth_mask->type)
		doca_log_buff(" type mask 0x%x",
			      rte_be_to_cpu_16(eth_mask->type));
	if (eth_spec && eth_spec->has_vlan)
		doca_log_buff(" has_vlan spec %u", eth_spec->has_vlan);
	if (eth_mask && eth_mask->has_vlan)
		doca_log_buff(" has_vlan mask %u", eth_mask->has_vlan);
	doca_log_buff(" / ");
}

static void doca_dump_ip4_item(const struct rte_flow_item *item)
{
	const struct rte_flow_item_ipv4 *ipv4_spec, *ipv4_mask;

	doca_log_buff("ipv4 ");
	ipv4_spec = (const struct rte_flow_item_ipv4 *)item->spec;
	ipv4_mask = (const struct rte_flow_item_ipv4 *)item->mask;
	if (ipv4_spec && ipv4_spec->hdr.src_addr)
		doca_log_ipv4("src is ",
			      rte_be_to_cpu_32(ipv4_spec->hdr.src_addr));
	if (ipv4_mask && ipv4_mask->hdr.src_addr)
		doca_log_ipv4("src mask ",
			      rte_be_to_cpu_32(ipv4_mask->hdr.src_addr));
	if (ipv4_spec && ipv4_spec->hdr.dst_addr)
		doca_log_ipv4("dst is ",
			      rte_be_to_cpu_32(ipv4_spec->hdr.dst_addr));
	if (ipv4_mask && ipv4_mask->hdr.dst_addr)
		doca_log_ipv4("dst mask ",
			      rte_be_to_cpu_32(ipv4_mask->hdr.dst_addr));
	if (ipv4_spec && ipv4_mask->hdr.next_proto_id)
		doca_log_buff("proto is 0x%x ", ipv4_spec->hdr.next_proto_id);
	if (ipv4_mask && ipv4_mask->hdr.next_proto_id)
		doca_log_buff("proto mask 0x%x ", ipv4_mask->hdr.next_proto_id);
	doca_log_buff("/ ");
}

static void doca_dump_upd_item(const struct rte_flow_item *item)
{
	const struct rte_flow_item_udp *udp_spec, *udp_mask;

	doca_log_buff("udp ");
	udp_spec = (const struct rte_flow_item_udp *)item->spec;
	udp_mask = (const struct rte_flow_item_udp *)item->mask;
	if (udp_spec && udp_spec->hdr.src_port)
		doca_log_buff("src is %u ",
			      rte_be_to_cpu_16(udp_spec->hdr.src_port));
	if (udp_mask && udp_mask->hdr.src_port)
		doca_log_buff("src mask %u ",
			      rte_be_to_cpu_16(udp_mask->hdr.src_port));
	if (udp_spec && udp_spec->hdr.dst_port)
		doca_log_buff("dst is %u ",
			      rte_be_to_cpu_16(udp_spec->hdr.dst_port));
	if (udp_mask && udp_mask->hdr.dst_port)
		doca_log_buff("dst mask 0x%x ",
			      rte_be_to_cpu_16(udp_mask->hdr.dst_port));
	doca_log_buff("/ ");
}

static void doca_dump_tcp_item(const struct rte_flow_item *item)
{
	const struct rte_flow_item_tcp *spec, *mask;

	doca_log_buff("tcp ");
	spec = (const struct rte_flow_item_tcp *)item->spec;
	mask = (const struct rte_flow_item_tcp *)item->mask;
	if (spec && spec->hdr.src_port)
		doca_log_buff("src is %u ",
			      rte_be_to_cpu_16(spec->hdr.src_port));
	if (mask && mask->hdr.src_port)
		doca_log_buff("src mask %u ",
			      rte_be_to_cpu_16(mask->hdr.src_port));
	if (spec && spec->hdr.dst_port)
		doca_log_buff("dst is %u ",
			      rte_be_to_cpu_16(spec->hdr.dst_port));
	if (mask && mask->hdr.dst_port)
		doca_log_buff("dst mask %u ",
			      rte_be_to_cpu_16(mask->hdr.dst_port));
	doca_log_buff("/ ");
}

static void doca_dump_vxlan_item(const struct rte_flow_item *item)
{
	uint32_t vni;
	const struct rte_flow_item_vxlan *spec, *mask;

	doca_log_buff("vxlan ");
	spec = (const struct rte_flow_item_vxlan *)item->spec;
	mask = (const struct rte_flow_item_vxlan *)item->mask;
	if (spec) {
		vni = (spec->vni[0] << 16U | spec->vni[1] << 8U | spec->vni[2]);
		if (vni)
			doca_log_buff("vni spec 0x%x ", vni);
	}
	if (mask) {
		vni = (mask->vni[0] << 16U | mask->vni[1] << 8U | mask->vni[2]);
		if (vni)
			doca_log_buff("vni mask 0x%x ", vni);
	}
	doca_log_buff("/ ");
}

static void doca_dump_gre_item(const struct rte_flow_item *item)
{
	const struct rte_flow_item_gre *spec, *mask;

	doca_log_buff("gre ");
	spec = (const struct rte_flow_item_gre *)item->spec;
	mask = (const struct rte_flow_item_gre *)item->mask;
	if (spec && spec->protocol)
		doca_log_buff("protocol spec 0x%x ",
			      rte_be_to_cpu_16(spec->protocol));
	if (mask && mask->protocol)
		doca_log_buff("protocol mask 0x%x ",
			      rte_be_to_cpu_16(mask->protocol));
	doca_log_buff("/ ");
}

static void doca_dump_gre_item_key(const struct rte_flow_item *item)
{
	const uint32_t *spec, *mask;

	doca_log_buff("gre_key  ");
	spec = (const uint32_t *)item->spec;
	mask = (const uint32_t *)item->mask;
	if (spec)
		doca_log_buff("value spec 0x%x ", rte_be_to_cpu_32(*spec));
	if (mask)
		doca_log_buff("value mask 0x%x ", rte_be_to_cpu_32(*mask));
	doca_log_buff("/ ");
}

void doca_dump_rte_flow(const char *name, uint16_t port_id,
			const struct rte_flow_attr *attr,
			const struct rte_flow_item items[],
			const struct rte_flow_action actions[])
{
	if (!doca_is_debug_level())
		return;
	memset(dump_buff, 0x0, sizeof(dump_buff));
	memset(prefix_buff, 0x0, sizeof(prefix_buff));
	doca_log_buff("  %s\nflow create %u %s %s group %u priority %u pattern ",
		      name, port_id, attr->ingress ? "ingress" : "egress",
		      attr->transfer ? "transfer" : "", attr->group,
		      attr->priority);

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		int item_type = items->type;

		switch (item_type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			doca_dump_eth_item(items);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			doca_dump_ip4_item(items);
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			doca_dump_upd_item(items);
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			doca_dump_tcp_item(items);
			break;
		case RTE_FLOW_ITEM_TYPE_ICMP:
			doca_log_buff("icmp / ");
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			doca_dump_vxlan_item(items);
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			doca_dump_gre_item(items);
			break;
		case RTE_FLOW_ITEM_TYPE_GRE_KEY:
			doca_dump_gre_item_key(items);
			break;
		default:
			doca_log_buff("not support item:%u\n", item_type);
		}
	}

	doca_log_buff("end actions ");
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		int action_type = actions->type;
		uint32_t queue_num;
		const struct rte_flow_action_mark *mark;
		const struct rte_flow_action_queue *queue;
		const struct rte_flow_action_jump *jump;
		const struct rte_flow_action_port_id *portid;
		const struct rte_flow_action_set_mac *set_mac;
		const struct rte_flow_action_set_ipv4 *set_ipv4;
		const struct rte_flow_action_set_tp *set_tp;
		const struct rte_flow_action_rss *rss;
		const struct rte_flow_action_meter *meter;
		const struct rte_flow_action_raw_encap *encap;
		const struct rte_flow_action_raw_decap *decap;

		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_MARK:
			mark =
			    (const struct rte_flow_action_mark *)actions->conf;
			doca_log_buff("mark id %u / ", mark->id);
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			queue =
			    (const struct rte_flow_action_queue *)actions->conf;
			doca_log_buff("queue index %u / ", queue->index);
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			jump =
			    (const struct rte_flow_action_jump *)actions->conf;
			doca_log_buff("jump group %u / ", jump->group);
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			rss = (const struct rte_flow_action_rss *)actions->conf;
			doca_log_buff("rss queues ");
			for (queue_num = 0; queue_num < rss->queue_num;
			     queue_num++)
				doca_log_buff("%u ", rss->queue[queue_num]);
			doca_log_buff("end / ");
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TP_DST:
			set_tp = (const struct rte_flow_action_set_tp *)
				     actions->conf;
			doca_log_buff("set_tp_dst port %u ",
				      rte_be_to_cpu_16(set_tp->port));
			doca_log_buff("/ ");
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TP_SRC:
			set_tp = (const struct rte_flow_action_set_tp *)
				     actions->conf;
			doca_log_buff("set_tp_src port %u ",
				      rte_be_to_cpu_16(set_tp->port));
			doca_log_buff("/ ");
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
			set_ipv4 = (const struct rte_flow_action_set_ipv4 *)
				       actions->conf;
			doca_log_ipv4("set_ipv4_src ipv4_addr ",
				      rte_be_to_cpu_32(set_ipv4->ipv4_addr));
			doca_log_buff("/ ");
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
			set_ipv4 = (const struct rte_flow_action_set_ipv4 *)
				       actions->conf;
			doca_log_ipv4("set_ipv4_dst ipv4_addr ",
				      rte_be_to_cpu_32(set_ipv4->ipv4_addr));
			doca_log_buff("/ ");
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
			set_mac = (const struct rte_flow_action_set_mac *)
				      actions->conf;
			doca_log_mac("set_mac_dst mac_addr ",
				     set_mac->mac_addr);
			doca_log_buff("/ ");
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			set_mac = (const struct rte_flow_action_set_mac *)
				      actions->conf;
			doca_log_mac("set_mac_src mac_addr ",
				     set_mac->mac_addr);
			doca_log_buff("/ ");
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			portid = (const struct rte_flow_action_port_id *)
				     actions->conf;
			doca_log_buff("port_id id %u / ", portid->id);
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			decap = (const struct rte_flow_action_raw_decap*)actions->conf;
			doca_log_buff("raw_decap (size:%zu)/ ", decap->size); /*need dump decap buff?*/
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			encap = (const struct rte_flow_action_raw_encap*)actions->conf;
			doca_log_buff("raw_encap (size:%zu)/ ", encap->size);
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			doca_log_buff("drop / ");
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			meter =
			    (const struct rte_flow_action_meter *)actions->conf;
			doca_log_buff("meter mtr_id %u  / ", meter->mtr_id);
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			doca_log_buff("count / ");
			break;
		default:
			doca_log_buff("not support action:%u /", action_type);
		}
	}
	doca_log_buff("end ");
	DOCA_LOG_DBG("%s", dump_buff);
}

static uint8_t doca_dump_ethhdr(uint8_t *data, uint32_t *len)
{
	uint16_t eth_type;
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;

	doca_log_mac("eth src-mac:", eth->s_addr.addr_bytes);
	doca_log_mac("dst-mac:", eth->d_addr.addr_bytes);
	doca_log_buff(",type:0x%x\n", eth->ether_type);
	eth_type = rte_be_to_cpu_16(eth->ether_type);
	*len = sizeof(struct rte_ether_hdr);
	switch (eth_type) {
	case RTE_ETHER_TYPE_IPV4:
		return DUMP_IPV4;
	default:
		printf("eth_type:0x%x not support.\n", eth_type);
		return DUMP_END;
	}
}

static uint8_t doca_dump_ipv4(uint8_t *data, uint32_t *len)
{
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)data;

	doca_log_ipv4("ip src:", rte_be_to_cpu_32(ip_hdr->src_addr));
	doca_log_ipv4("dst:", rte_be_to_cpu_32(ip_hdr->dst_addr));
	doca_log_buff("proto:%d\n", ip_hdr->next_proto_id);
	*len = sizeof(struct rte_ipv4_hdr);
	switch (ip_hdr->next_proto_id) {
	case IPPROTO_UDP:
		return DUMP_UDP;
	case IPPROTO_GRE:
		return DUMP_GRE;
	case IPPROTO_TCP:
		return DUMP_TCP;
	default:
		printf("unsupport layer 4 type:0x%x\n", ip_hdr->next_proto_id);
		return DUMP_END;
	}
}

static uint8_t doca_dump_gre(uint8_t *data, uint32_t *len)
{
	uint16_t proto;
	uint32_t key;
	struct rte_gre_hdr *gre_hdr = (struct rte_gre_hdr *)data;

	proto = rte_be_to_cpu_16(gre_hdr->proto);
	doca_log_buff("gre proto:0x%x", proto);
	*len = sizeof(struct rte_gre_hdr);
	if (gre_hdr->k) {
		*len += sizeof(uint32_t);
		key = *((uint32_t *)(gre_hdr + 1));
		doca_log_buff(",key:0x%x", rte_be_to_cpu_32(key));
	}
	switch (proto) {
	case RTE_ETHER_TYPE_IPV4:
		doca_log_buff("\n");
		return DUMP_IPV4;
	default:
		printf("unsupport gre protocal:0x%x\n", proto);
		return DUMP_END;
	}
}

static uint8_t doca_dump_vxlan(uint8_t *data, uint32_t *len)
{
	struct rte_vxlan_hdr *vxlan = (struct rte_vxlan_hdr *)data;

	*len = sizeof(struct rte_vxlan_hdr);
	doca_log_buff("vxlan flags:0x%x vni:0x%x\n",
		      rte_be_to_cpu_32(vxlan->vx_flags) >> 24,
		      rte_be_to_cpu_32(vxlan->vx_vni) >> 8);
	return DUMP_ETH;
}

static uint8_t doca_dump_udp(uint8_t *data, uint32_t *len)
{
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)data;

	*len = sizeof(struct rte_udp_hdr);
	doca_log_buff("udp src-port:%d dst-port:%d",
		      rte_be_to_cpu_16(udp->src_port),
		      rte_be_to_cpu_16(udp->dst_port));
	if (rte_be_to_cpu_16(udp->dst_port) == DOCA_VXLAN_DEFAULT_PORT) {
		doca_log_buff("\n");
		return DUMP_VXLAN;
	}
	return DUMP_END;
}

static uint8_t doca_dump_tcp(uint8_t *data, uint32_t *len)
{
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)data;

	*len = sizeof(struct rte_tcp_hdr);
	doca_log_buff("tcp src-port:%d dst-port:%d\n",
		      rte_be_to_cpu_16(tcp->src_port),
		      rte_be_to_cpu_16(tcp->dst_port));
	return DUMP_END;
}

struct dump_hdr doca_dump_hdr[] = {
	{DUMP_ETH,	 doca_dump_ethhdr},
	{DUMP_IPV4,	 doca_dump_ipv4},
	{DUMP_UDP,	 doca_dump_udp},
	{DUMP_TCP,	 doca_dump_tcp},
	{DUMP_VXLAN, doca_dump_vxlan},
	{DUMP_GRE,	 doca_dump_gre},
};

static void doca_dump_packet_buff(uint8_t *head, uint32_t len)
{
	uint32_t length;
	uint16_t next_protocal;

	next_protocal = DUMP_ETH;
	while (len) {
		next_protocal =
		    doca_dump_hdr[next_protocal].dump_hdr(head, &length);
		if (next_protocal == DUMP_END)
			break;
		len -= length;
		head += length;
		doca_inc_line_prefix();
	}
}

void doca_dump_rte_mbuff(const char *name, struct rte_mbuf *mb)
{
	uint8_t *ethdr;
	struct rte_ether_hdr _eth_hdr;

	if (!doca_is_debug_level())
		return;
	memset(dump_buff, 0x0, sizeof(dump_buff));
	memset(prefix_buff, 0x0, sizeof(prefix_buff));
	doca_log_buff("%sport:%d mbuff on core:%u,pkt_len:%u,"
		"data_len:%u,nb_segs:%u,ol_flags:0x%lx\n",
	    name, mb->port, rte_lcore_id(), mb->pkt_len,
	    mb->data_len, mb->nb_segs, mb->ol_flags);
	ethdr = (uint8_t *)((uintptr_t)rte_pktmbuf_read(mb, 0, sizeof(_eth_hdr),
						     &_eth_hdr));
	doca_dump_packet_buff(ethdr, mb->data_len);
	DOCA_LOG_DBG("%s", dump_buff);
}

void doca_dump_flow_actions(struct doca_flow_actions *actions)
{
	char dump_buff[MAX_TMP_BUFF] = {'\0'};

	if (!doca_is_debug_level())
		return;
	memset(dump_buff, 0x0, sizeof(dump_buff));
	doca_log_buff("modify action:");
	doca_log_buff("\n    decap:%d", actions->decap);
	if (!doca_is_mac_zero(actions->mod_src_mac))
		doca_log_mac("\n    src-mac:", actions->mod_src_mac);
	if (!doca_is_mac_zero(actions->mod_dst_mac))
		doca_log_mac("\n    dst-mac:", actions->mod_dst_mac);
	if (!doca_is_ip_zero(&actions->mod_src_ip))
		doca_log_ipv4(
		    "\n    src-ipv4:",
		    rte_be_to_cpu_32(actions->mod_src_ip.a.ipv4_addr));
	if (!doca_is_ip_zero(&actions->mod_dst_ip))
		doca_log_ipv4(
		    "\n    dst-ipv4:",
		    rte_be_to_cpu_32(actions->mod_dst_ip.a.ipv4_addr));
	if (actions->mod_src_port)
		doca_log_buff("\n    src-port:0x%x",
			      rte_be_to_cpu_16(actions->mod_src_port));
	if (actions->mod_dst_port)
		doca_log_buff("\n    dst-port:0x%x",
			      rte_be_to_cpu_16(actions->mod_dst_port));
	DOCA_LOG_DBG("%s\n", dump_buff);
}

static const char *doca_l4_type(uint8_t l4_type)
{
	switch (l4_type) {
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_GRE:
		return "gre";
	default:
		return "unknown";
	}
}

void doca_dump_flow_match(struct doca_flow_match *match)
{
	char dump_buff[MAX_TMP_BUFF] = {'\0'};

	if (!doca_is_debug_level())
		return;
	memset(dump_buff, 0x0, sizeof(dump_buff));
	doca_log_buff("match items:");
	if (!doca_is_mac_zero(match->out_src_mac))
		doca_log_mac("\n    outer-src-mac:", match->out_src_mac);
	if (!doca_is_mac_zero(match->out_dst_mac))
		doca_log_mac("\n    outer-dst-mac:", match->out_dst_mac);
	if (match->vlan_id)
		doca_log_buff("\n  vlan-id:0x%x", match->vlan_id);
	if (!doca_is_ip_zero(&match->out_src_ip))
		doca_log_ipv4("\n    outer-src-ip:",
			      rte_be_to_cpu_32(match->out_src_ip.a.ipv4_addr));
	if (!doca_is_ip_zero(&match->out_dst_ip))
		doca_log_ipv4("\n    outer-dst-ip:",
			      rte_be_to_cpu_32(match->out_dst_ip.a.ipv4_addr));
	if (match->out_l4_type)
		doca_log_buff("\n    outer-l4-type:%u[%s]", match->out_l4_type,
			      doca_l4_type(match->out_l4_type));
	if (match->out_src_port)
		doca_log_buff("\n    outer-src-port:%u",
			      rte_be_to_cpu_16(match->out_src_port));
	if (match->out_dst_port)
		doca_log_buff("\n    outer-dst-port:%u",
			      rte_be_to_cpu_16(match->out_dst_port));
	switch (match->tun.type) {
	case DOCA_TUN_VXLAN:
		doca_log_buff("\n    tun-type:vxlan,vni:0x%x",
			      rte_be_to_cpu_32(match->tun.vxlan.tun_id));
		break;
	case DOCA_TUN_GRE:
		doca_log_buff("\n    tun-type:gre,key:0x%x",
			      rte_be_to_cpu_32(match->tun.gre.key));
		break;
	case DOCA_TUN_NONE:
		doca_log_buff("\n    tun-type:none");
		break;
	}
	if (!doca_is_ip_zero(&match->in_src_ip))
		doca_log_ipv4("\n    inner-src-ip:",
			      rte_be_to_cpu_32(match->in_src_ip.a.ipv4_addr));
	if (!doca_is_ip_zero(&match->in_dst_ip))
		doca_log_ipv4("\n    inner-dst-ip:",
			      rte_be_to_cpu_32(match->in_dst_ip.a.ipv4_addr));
	if (match->in_l4_type)
		doca_log_buff("\n    inner-l4-type:%u[%s]", match->in_l4_type,
			      doca_l4_type(match->in_l4_type));
	if (match->in_src_port)
		doca_log_buff("\n    inner-src-port:0x%x",
			      rte_be_to_cpu_16(match->in_src_port));
	if (match->in_dst_port)
		doca_log_buff("\n    inner-dst-port:0x%x",
			      rte_be_to_cpu_16(match->in_dst_port));
	DOCA_LOG_DBG("%s\n", dump_buff);
}
