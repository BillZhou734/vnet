#include <stdlib.h>
#include "doca_id_pool.h"

static void doca_id_pool_init(struct doca_id_pool *pool,
			      struct doca_id_pool_cfg *cfg)
{
	int i;
	int n = cfg->min;

	for (i = 0; i < cfg->size; i++)
		pool->keys_arr[i] = n++;
	pool->idx = 0;
	pool->size = cfg->size;
}

struct doca_id_pool *doca_id_pool_create(struct doca_id_pool_cfg *cfg)
{
	struct doca_id_pool *pool;

	pool = (struct doca_id_pool *)malloc(sizeof(struct doca_id_pool) +
					     sizeof(int) * cfg->size);
	if (pool != NULL)
		doca_id_pool_init(pool, cfg);
	return pool;
}

int doca_id_pool_alloc_id(struct doca_id_pool *pool)
{
	if (pool == NULL)
		return -1;
	if (pool->idx == pool->size)
		return -1;
	return pool->keys_arr[pool->idx++];
}

void doca_id_pool_free(struct doca_id_pool *pool, int id)
{
	if (pool == NULL)
		return;
	if (pool->idx <= 0)
		return;
	pool->keys_arr[--pool->idx] = id;
}

bool doca_id_pool_has_ids(struct doca_id_pool *pool)
{
	if (pool == NULL)
		return false;
	return pool->size == pool->idx;
}

void doca_id_pool_destroy(struct doca_id_pool *pool)
{
	free(pool);
}
