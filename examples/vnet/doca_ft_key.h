#ifndef _GW_FT_KEY_H_
#define _GW_FT_KEY_H_


#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>


struct doca_pkt_info;

struct doca_ft_key {
    uint32_t ipv4_1;
    uint32_t ipv4_2;
    uint16_t port_1;
    uint16_t port_2;
    uint32_t vni;
    uint8_t	protocol;
    uint8_t	tun_type;
	uint8_t pad[6];
	uint32_t rss_hash;
};

/**
 * @brief - build table key according to parsed packet.
 *
 * @param m
 * @param key
 *
 * @return 0 on success 
 */
int doca_ft_key_fill(struct doca_pkt_info *m, struct doca_ft_key *key);

/**
 * @brief - compare keys
 *
 * @param key1
 * @param key2
 *
 * @return true if keys are equal.
 */
bool doca_ft_key_equal(struct doca_ft_key *key1, struct doca_ft_key *key2);

#endif
