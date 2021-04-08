#ifndef _GW_FT_H_
#define _GW_FT_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <rte_mbuf.h>
#include "doca_pkt.h"

struct doca_ft;
struct doca_ft_key;

struct doca_ft_user_ctx {
    uint32_t fid;
    uint8_t  data[0];
};


/**
 * @brief - create new flow table
 *
 * @param size             - number of flows
 * @param user_data_size   - private data for user
 *
 * @return pointer to new allocated flow table or NULL
 */
struct doca_ft *doca_ft_create(int size, uint32_t user_data_size, 
                               void (*gw_aging_cb)(struct doca_ft_user_ctx *ctx),
                               void (*gw_aging_hw_cb)(void));

void doca_ft_destroy(struct doca_ft *ft);

bool doca_ft_add_new(struct doca_ft *ft, struct doca_pkt_info *pinfo,struct doca_ft_user_ctx **ctx);

bool doca_ft_find(struct doca_ft *ft, struct doca_pkt_info *pinfo, 
                                 struct doca_ft_user_ctx **ctx);

int doca_ft_destory_flow(struct doca_ft *ft, struct doca_ft_key *key);

#endif
