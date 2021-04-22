#include "rte_ether.h"
#include "rte_mbuf.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_gre.h"
#include "rte_gtp.h"
#include "rte_vxlan.h"

#include "doca_pkt.h"
#include "doca_log.h"

DOCA_LOG_MODULE(doca_pkt);

#define DOCA_GTP_ESPN_FLAGS_ON(p) (p & 0x7)
#define DOCA_GTP_EXT_FLAGS_ON(p) (p & 0x4)

uint32_t doca_pinfo_outer_ipv4_dst(struct doca_pkt_info *pinfo)
{
	return ((struct rte_ipv4_hdr *)pinfo->outer.l3)->dst_addr;
}

uint32_t doca_pinfo_outer_ipv4_src(struct doca_pkt_info *pinfo)
{
	return ((struct rte_ipv4_hdr *)pinfo->outer.l3)->src_addr;
}

uint32_t doca_pinfo_inner_ipv4_dst(struct doca_pkt_info *pinfo)
{
	return ((struct rte_ipv4_hdr *)pinfo->inner.l3)->dst_addr;
}

uint32_t doca_pinfo_inner_ipv4_src(struct doca_pkt_info *pinfo)
{
	return ((struct rte_ipv4_hdr *)pinfo->inner.l3)->src_addr;
}

static uint16_t doca_pinfo_src_port(struct doca_pkt_format *fmt)
{
	switch (fmt->l4_type) {
	case IPPROTO_TCP:
		return ((struct rte_tcp_hdr *)fmt->l4)->src_port;
	case IPPROTO_UDP:
		return ((struct rte_udp_hdr *)fmt->l4)->src_port;
	default:
		return 0;
	}
}

static uint16_t doca_pinfo_dst_port(struct doca_pkt_format *fmt)
{
	switch (fmt->l4_type) {
	case IPPROTO_TCP:
		return ((struct rte_tcp_hdr *)fmt->l4)->dst_port;
	case IPPROTO_UDP:
		return ((struct rte_udp_hdr *)fmt->l4)->dst_port;
	default:
		return 0;
	}
}

uint16_t doca_pinfo_inner_src_port(struct doca_pkt_info *pinfo)
{
	return doca_pinfo_src_port(&pinfo->inner);
}

uint16_t doca_pinfo_inner_dst_port(struct doca_pkt_info *pinfo)
{
	return doca_pinfo_dst_port(&pinfo->inner);
}

uint16_t doca_pinfo_outer_src_port(struct doca_pkt_info *pinfo)
{
	return doca_pinfo_src_port(&pinfo->outer);
}

uint16_t doca_pinfo_outer_dst_port(struct doca_pkt_info *pinfo)
{
	return doca_pinfo_dst_port(&pinfo->outer);
}

static int doca_parse_pkt_format(uint8_t *data, int len, bool l2,
				 struct doca_pkt_format *fmt)
{
	struct rte_ether_hdr *eth = NULL;
	struct rte_ipv4_hdr *iphdr;
	int l3_off = 0;
	int l4_off = 0;
	int l7_off = 0;

	fmt->l2 = data;
	if (l2) {
		eth = (struct rte_ether_hdr *)data;
		fmt->l2 = data;
		switch (rte_be_to_cpu_16(eth->ether_type)) {
		case RTE_ETHER_TYPE_IPV4:
			l3_off = sizeof(struct rte_ether_hdr);
			break;
		case RTE_ETHER_TYPE_IPV6:
			l3_off = sizeof(struct rte_ether_hdr);
			fmt->l3_type = 6;
			return -1;
		case RTE_ETHER_TYPE_ARP:
		default:
			DOCA_LOG_WARN("unsupported l2 type %x",
				eth->ether_type);
			return -1;
		}
	}

	iphdr = (struct rte_ipv4_hdr *)(data + l3_off);
	if ((iphdr->version_ihl >> 4) != 4)
		return -1;
	if (iphdr->src_addr == 0 || iphdr->dst_addr == 0)
		return -1;
	fmt->l3 = (data + l3_off);
	fmt->l3_type = GW_IPV4;
	l4_off = l3_off + rte_ipv4_hdr_len(iphdr);
	fmt->l4 = data + l4_off;
	switch (iphdr->next_proto_id) {
	case IPPROTO_TCP:
	{
		struct rte_tcp_hdr *tcphdr =
		    (struct rte_tcp_hdr *)(data + l4_off);

		l7_off = l4_off + ((tcphdr->data_off & 0xf0) >> 2);
		if (l7_off > len)
			return -1;
		fmt->l4_type = IPPROTO_TCP;
		fmt->l7 = (data + l7_off);
		break;
	}
	case IPPROTO_UDP:
	{
		struct rte_udp_hdr *udphdr =
		    (struct rte_udp_hdr *)(data + l4_off);

		l7_off = l4_off + sizeof(*udphdr);
		fmt->l4_type = IPPROTO_UDP;
		if (l7_off > len)
			return -1;
		fmt->l7 = (data + l7_off);
		break;
	}
	case IPPROTO_GRE:
		fmt->l4_type = IPPROTO_GRE;
		break;
	case IPPROTO_ICMP:
		fmt->l4_type = IPPROTO_ICMP;
		break;
	default:
		DOCA_LOG_INFO("unsupported l4 %d\n", iphdr->next_proto_id);
		return -1;
	}
	return 0;
}

static int doca_parse_is_tun(struct doca_pkt_info *pinfo)
{
	if (pinfo->outer.l3_type != GW_IPV4)
		return 0;

	if (pinfo->outer.l4_type == IPPROTO_GRE) {
		int optional_off = 0;
		struct rte_gre_hdr *gre_hdr =
		    (struct rte_gre_hdr *)pinfo->outer.l4;
		if (gre_hdr->c)
			return -1;
		if (gre_hdr->k) {
			optional_off += 4;
			pinfo->tun.vni =
			    *(uint32_t *)(pinfo->outer.l4 +
					  sizeof(struct rte_gre_hdr));
			pinfo->tun.l2 = true;
		}
		if (gre_hdr->s)
			optional_off += 4;
		pinfo->tun_type = APP_TUN_GRE;
		pinfo->tun.proto = gre_hdr->proto;
		return sizeof(struct rte_gre_hdr) + optional_off;
	}

	if (pinfo->outer.l4_type == IPPROTO_UDP) {
		struct rte_udp_hdr *udphdr =
		    (struct rte_udp_hdr *)pinfo->outer.l4;
		uint8_t *udp_data =
		    pinfo->outer.l4 + sizeof(struct rte_udp_hdr);

		switch (rte_cpu_to_be_16(udphdr->dst_port)) {
		case GW_VXLAN_PORT:
		{
			struct rte_vxlan_gpe_hdr *vxlanhdr =
			    (struct rte_vxlan_gpe_hdr *)udp_data;

			if (vxlanhdr->vx_flags & 0x08) {
				/*need to check if this gpe*/
				pinfo->tun_type = APP_TUN_VXLAN;
				pinfo->tun.vni = vxlanhdr->vx_vni;
				pinfo->tun.l2 = true;
			}
			return sizeof(struct rte_vxlan_gpe_hdr) +
			       sizeof(struct rte_udp_hdr);
		}
		case DOCA_GTPU_PORT:
		{
			int off = sizeof(struct rte_gtp_hdr) +
				  sizeof(struct rte_udp_hdr);
			struct rte_gtp_hdr *gtphdr =
			    (struct rte_gtp_hdr *)udp_data;

			pinfo->tun_type = APP_TUN_GTPU;
			pinfo->tun.vni = gtphdr->teid;
			pinfo->tun.gtp.msg_type = gtphdr->msg_type;
			pinfo->tun.gtp.flags = gtphdr->gtp_hdr_info;
			pinfo->tun.l2 = false;
			if (DOCA_GTP_ESPN_FLAGS_ON(pinfo->tun.gtp.flags))
				off += 4;
			printf("GTP tun = %u\n",
			       rte_cpu_to_be_32(pinfo->tun.vni));
			return off;
		}
		default:
			return 0;
		}
	}
	return 0;
}

/**
 * @brief - parse packet and extract outer/inner + tunnels and
 *  put in packet info
 *
 * @param data    - packet raw data (including eth)
 * @param len     - len of the packet
 * @param pinfo   - extracted info is set here
 *
 * @return 0 on success and error otherwise.
 */
int doca_parse_packet(uint8_t *data, int len, struct doca_pkt_info *pinfo)
{
	int off = 0;
	int inner_off = 0;

	if (!pinfo) {
		DOCA_LOG_ERR("pinfo =%p\n", pinfo);
		return -1;
	}
	pinfo->len = len;
	if (doca_parse_pkt_format(data, len, true, &pinfo->outer))
		return -1;

	off = doca_parse_is_tun(pinfo);
	if (pinfo->tun_type == APP_TUN_NONE || off < 0)
		return 0;

	switch (pinfo->tun_type) {
	case APP_TUN_GRE:
		inner_off = (pinfo->outer.l4 - data) + off;
		if (doca_parse_pkt_format(data + inner_off, len - inner_off,
					  false, &pinfo->inner))
			return -1;
		break;
	case APP_TUN_VXLAN:
		inner_off = (pinfo->outer.l4 - data) + off;
		if (doca_parse_pkt_format(data + inner_off, len - inner_off,
					  pinfo->tun.l2, &pinfo->inner))
			return -1;
		break;
	case APP_TUN_GTPU:
		inner_off = (pinfo->outer.l4 - data) + off;
		if (doca_parse_pkt_format(data + inner_off, len - inner_off,
					  pinfo->tun.l2, &pinfo->inner))
			return -1;
		break;
	default:
		break;
	}
	return 0;
}

void doca_pinfo_decap(struct doca_pkt_info *pinfo)
{
	switch (pinfo->tun_type) {
	case APP_TUN_GRE:
		DOCA_LOG_ERR("decap for GRE not supported");
		break;
	case APP_TUN_VXLAN:
		pinfo->outer.l2 = pinfo->inner.l2;
		pinfo->outer.l3 = pinfo->inner.l3;
		pinfo->outer.l4 = pinfo->inner.l4;
		pinfo->outer.l7 = pinfo->inner.l7;
		pinfo->tun_type = APP_TUN_NONE;
		break;
	default:
		break;
	}
}
