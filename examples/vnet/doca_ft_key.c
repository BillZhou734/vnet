#include <stdio.h>
#include <arpa/inet.h>
#include "gw.h"
#include "doca_ft_key.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"

#define doca_ft_key_get_ipv4_src(inner,pinfo) inner?doca_pinfo_inner_ipv4_src(pinfo): \
                                            doca_pinfo_outer_ipv4_src(pinfo);

#define doca_ft_key_get_ipv4_dst(inner,pinfo) inner?doca_pinfo_inner_ipv4_dst(pinfo): \
                                            doca_pinfo_outer_ipv4_dst(pinfo);

#define doca_ft_key_get_src_port(inner,pinfo) inner?doca_pinfo_inner_src_port(pinfo): \
                                            doca_pinfo_outer_src_port(pinfo);

#define doca_ft_key_get_dst_port(inner,pinfo) inner?doca_pinfo_inner_dst_port(pinfo): \
                                            doca_pinfo_outer_dst_port(pinfo);

int doca_ft_key_fill(struct doca_pkt_info *pinfo, struct doca_ft_key *key)
{
    bool inner = false;

    if ( pinfo->tun_type != APP_TUN_NONE )
        inner = true; 

    //TODO: support ipv6
    if ( pinfo->outer.l3_type != GW_IPV4) {
        return -1;
    }

	key->rss_hash = pinfo->rss_hash;
    /* 5-tuple of inner if there is tunnel or outer if none */
    key->protocol = inner?pinfo->inner.l4_type:pinfo->outer.l4_type;
    key->ipv4_1 = doca_ft_key_get_ipv4_src(inner,pinfo);
    key->ipv4_2 = doca_ft_key_get_ipv4_dst(inner,pinfo);
    key->port_1 = doca_ft_key_get_src_port(inner,pinfo);
    key->port_2 = doca_ft_key_get_dst_port(inner,pinfo);

    /* in case of tunnel , use tun tyoe and vni */
    if ( pinfo->tun_type != APP_TUN_NONE ) {
        key->tun_type = pinfo->tun_type;
        key->vni = pinfo->tun.vni;
	}
    return 0;
}

bool doca_ft_key_equal(struct doca_ft_key *key1, struct doca_ft_key *key2)
{
	uint64_t *keyp1 = (uint64_t*)key1;
	uint64_t *keyp2 = (uint64_t*)key2;
	uint64_t res = keyp1[0] ^ keyp2[0];

	res |= keyp1[1] ^ keyp2[1];
	res |= keyp1[2] ^ keyp2[2];
	return (res == 0);
}
