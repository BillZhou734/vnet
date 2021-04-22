#ifndef _DOCA_ID_POOL_H_
#define _DOCA_ID_POOL_H_

#include <stdint.h>
#include <stdbool.h>

struct doca_id_pool {
	int idx;
	int size;
	int keys_arr[0];
};

struct doca_id_pool_cfg {
	int size;
	int min;
};

struct doca_id_pool *doca_id_pool_create(struct doca_id_pool_cfg *cfg);

void doca_id_pool_destroy(struct doca_id_pool *pool);

int doca_id_pool_alloc_id(struct doca_id_pool *pool);

void doca_id_pool_free(struct doca_id_pool *pool, int id);

bool doca_id_pool_has_ids(struct doca_id_pool *pool);

static inline int doca_id_pool_get_used(struct doca_id_pool *pool)
{
	return pool->idx;
}

#endif
