#ifndef _DOCA_NET_H_
#define _DOCA_NET_H_

#define DOCA_TCP  (0x6)
#define DOCA_ETHER_ADDR_LEN (6)
#define DOCA_VXLAN_DEFAULT_PORT (4789)

enum doca_gw_l3_type {
	DOCA_NONE = 0,
    DOCA_IPV4 = 4,
    DOCA_IPV6 = 6,
};

enum doca_gw_tun_type {
    DOCA_TUN_NONE = 0,
    DOCA_TUN_VXLAN,
    DOCA_TUN_GRE,
};

enum doca_modify_flags{
	DOCA_MODIFY_SMAC	= (1 << 0),
	DOCA_MODIFY_DMAC	= (1 << 1),
	DOCA_MODIFY_VLAN_ID	= (1 << 2),
	DOCA_MODIFY_SIP		= (1 << 3),
	DOCA_MODIFY_DIP		= (1 << 4),
	DOCA_MODIFY_SPORT	= (1 << 5),
	DOCA_MODIFY_DPORT	= (1 << 6),
	DOCA_MODIFY_GRE_KEY	= (1 << 7),
	DOCA_MODIFY_VXLAN_VNI	= (1 << 8),
};

struct doca_gw_tun {
    enum doca_gw_tun_type type;
    union {
        struct vxlan {
            uint32_t tun_id;
        } vxlan;

        struct gre {
            uint32_t key;
        }gre;

    };
};

struct doca_ip_addr {
    uint8_t type;
    union {
        uint32_t ipv4_addr;
        uint32_t ipv6_addr[4]; 
    } a;
};

#endif
