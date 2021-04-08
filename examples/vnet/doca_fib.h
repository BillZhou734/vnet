#ifndef _DOCA_FIB_H_
#define _DOCA_FIB_H_

#include <rte_ether.h>
#include <stdint.h>
#include "doca_net.h"
/**
 * 
 * FIB table
 * ip to mac address.
 * Can be attached to offload, where mac by fib flag is used.
 */

struct doca_fib_tbl;

struct doca_fib_tbl *doca_create_fib_tbl(uint32_t _size);

void doca_destroy_fib_tbl(struct doca_fib_tbl* table);

int
doca_add_fib_tbl_entry(struct doca_fib_tbl* table, const uint32_t *ip_addr,
                    uint8_t mac[DOCA_ETHER_ADDR_LEN]);

int
doca_remove_fib_tbl_entry(struct doca_fib_tbl* table, const uint32_t *ip_addr);

int
doca_lookup_fib_tbl_entry(struct doca_fib_tbl* table, uint32_t *ip_addr,
                          uint8_t mac[DOCA_ETHER_ADDR_LEN]);


#endif
