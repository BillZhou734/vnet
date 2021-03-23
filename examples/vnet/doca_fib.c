#include "doca_fib.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_lpm.h>
#include <rte_hash.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_memcpy.h>
#include <rte_random.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

#include "doca_log.h"
#include "doca_fib.h"
#include "doca_net.h"

DOCA_LOG_MODULE(doca_fib)

struct doca_fib_tbl_entry {
    uint32_t ip_addr;
    struct rte_ether_addr mac;
};

struct doca_fib_tbl {
    int size;
    struct rte_hash *handler;
    struct doca_fib_tbl_entry items[0];
};

struct doca_fib_tbl *doca_create_fib_tbl(uint32_t _size)
{
  struct doca_fib_tbl *table;
  uint32_t seed = (uint32_t) rte_rand();
  uint32_t size = (uint32_t) (!rte_is_power_of_2(_size))?rte_align32pow2(_size):_size;

  table = (struct doca_fib_tbl*) malloc(sizeof(struct doca_fib_tbl) + sizeof(struct doca_fib_tbl_entry) * size);
  if (table == NULL) {
    DOCA_LOG_ERR("cannot allocate memory for table.\n");
    return NULL;
  }
  
  struct rte_hash_parameters params = {
    .name = "fib_table",
    .entries = size,
    //.bucket_entries = RTE_HASH_BUCKET_ENTRIES_MAX,
    .key_len = 4,
    .hash_func = rte_jhash,
    .hash_func_init_val = seed,
    .socket_id = (int) rte_socket_id()
  };
  table->handler = rte_hash_create(&params);
  if (table->handler == NULL) {
    DOCA_LOG_ERR( "cannot create rte_hash: %s.\n", rte_strerror(rte_errno));
    goto free;
  }

  DOCA_LOG_INFO("new fib table allocated");

  return table;
free:
  free(table->handler);
  free(table);
  return NULL;  
}

void doca_destroy_fib_tbl(struct doca_fib_tbl* table)
{
  rte_hash_free(table->handler);
  free(table->items);
}

int
doca_add_fib_tbl_entry(struct doca_fib_tbl* table, const uint32_t *ip_addr,
                    uint8_t mac[DOCA_ETHER_ADDR_LEN])
{
  int32_t key = rte_hash_add_key(table->handler, ip_addr);
  if (key >= 0) {
    struct doca_fib_tbl_entry *entry = &table->items[key];
    memcpy(&entry->mac, mac, DOCA_ETHER_ADDR_LEN); 
    entry->ip_addr = *ip_addr;
//    entry->expire = 0;
    return 0;
  }

  if (key == -ENOSPC) {
    DOCA_LOG_WARN("no space in the hash for this key.");
  }
  switch (-key) {
    case EINVAL:
      DOCA_LOG_WARN("Invalid parameters.");
      break;
    case ENOSPC:
      DOCA_LOG_WARN("no space in the hash for this key.");
  }
  return key;
}

int
doca_remove_fib_tbl_entry(struct doca_fib_tbl* table, const uint32_t *ip_addr)
{
  int32_t key = rte_hash_del_key(table->handler, ip_addr);
  if (key >= 0) {
    struct doca_fib_tbl_entry *entry = &table->items[key];
    memset(&entry->mac,0, DOCA_ETHER_ADDR_LEN);
    entry->ip_addr = 0;
//    entry->expire = 0;
    return 0;
  }

  switch (-key) {
    case EINVAL:
      DOCA_LOG_WARN("Invalid parameters.\n");
      break;
    case ENOENT:
      DOCA_LOG_WARN("the key is not found.\n");
  }
  return key;
}

int
doca_lookup_fib_tbl_entry(struct doca_fib_tbl* table, uint32_t *ip_addr,
                        uint8_t mac[DOCA_ETHER_ADDR_LEN])
{
  int32_t key = rte_hash_lookup(table->handler, (void*) ip_addr);
  if (key >= 0) {
    struct doca_fib_tbl_entry *entry = &table->items[key];
    memcpy(mac, &entry->mac, DOCA_ETHER_ADDR_LEN);
    return 0;
  }
  switch (-key) {
    case EINVAL:
      DOCA_LOG_WARN("Invalid parameters.");
      break;
    case ENOENT:
      ;
      //RTE_LOG(WARNING, ARP_TABLE, "the key is not found.\n");
      /* break through */
  }
  return key;
}

