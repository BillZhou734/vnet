#include <unistd.h>
#include <stdio.h>
#include "rte_mbuf.h"
#include "doca_ft.h"
#include "doca_ft_key.h"
#include "rte_hash_crc.h"
#include "rte_malloc.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_spinlock.h"

#include "doca_log.h"
#include "doca_kpi.h"


DOCA_LOG_MODULE(flow_table)

static int _doca_ft_destory_flow(struct doca_ft *ft, struct doca_ft_key *key);

struct doca_ft_entry {
    LIST_ENTRY(doca_ft_entry) next; /* entry pointers in the list. */
    struct doca_ft_key key;
    uint64_t expiration;
    uint64_t last_counter;
    uint64_t sw_ctr;
    uint8_t hw_off;

    struct doca_ft_user_ctx user_ctx;
};

LIST_HEAD(doca_ft_entry_head, doca_ft_entry );

struct doca_ft_bucket {
    struct doca_ft_entry_head head;
    rte_spinlock_t lock;
};


struct doca_ft_stats {
    uint64_t add;
    uint64_t rm;

    uint64_t memuse;
};

struct doca_ft_cfg {
    uint32_t size;
    uint32_t mask;
    uint32_t user_data_size;
    uint32_t entry_size;
};

struct doca_ft {
    struct doca_ft_cfg cfg;
    struct doca_ft_stats stats;
    volatile int stop_aging_thread;
    uint32_t fid_ctr;

    struct doca_gauge *cps_gauge;

    void (*gw_aging_cb)(struct doca_ft_user_ctx *ctx);
    void (*gw_aging_hw_cb)(void);
    struct doca_ft_bucket buckets[0];
};

static
void doca_ft_update_expiration(struct doca_ft_entry *e)
{
    uint64_t t  =  rte_rdtsc();
    uint64_t sec = rte_get_timer_hz();
    e->expiration = t + sec*10;
}

static void * doca_ft_aging_main(void *void_ptr)
{
    unsigned int i;
    struct doca_ft * ft = (struct doca_ft *) void_ptr; 
    struct doca_ft_entry_head *first;
    struct doca_ft_entry *node;
    if (!ft){
        DOCA_LOG_CRIT("no ft, abort aging\n");
        return NULL;
    }

    while(!ft->stop_aging_thread){
        uint64_t t = rte_rdtsc();

        if ((int) (ft->stats.add - ft->stats.rm) == 0){
            continue;
        }
        DOCA_LOG_INFO("total entries: %d", (int) (ft->stats.add - ft->stats.rm));
        DOCA_LOG_INFO("total adds   : %d", (int) (ft->stats.add));
        DOCA_LOG_INFO("cps: %d",doca_gauge_get_sum(ft->cps_gauge));

        for(i = 0 ; i < ft->cfg.size ; i++){
            bool still_aging = false;
            do {
                still_aging = false;
                if (rte_spinlock_trylock(&ft->buckets[i].lock)){
                    first = &ft->buckets[i].head;
                    LIST_FOREACH(node, first, next) {
                        if(node->hw_off) {
                            /* TODO: support in HW */
                        }
                        if(node->expiration < t){
                            DOCA_LOG_DBG("removing flow");
                            _doca_ft_destory_flow(ft, &node->key);
                            still_aging = true;
                            break;
                        }
                    }
                    rte_spinlock_unlock(&ft->buckets[i].lock);
                }
            } while(still_aging);
        }
        sleep(1);
    }

    return NULL;
}

/**
 * @brief - start per flow table aging thread
 *
 * @param ft
 */
static void doca_ft_aging_thread_start(struct doca_ft *ft)
{
    pthread_t inc_x_thread;

    // create a second thread which executes inc_x(&x) 
    if(pthread_create(&inc_x_thread, NULL, doca_ft_aging_main, ft)) {
        fprintf(stderr, "Error creating thread\n");
    }
}

static uint32_t doca_ft_key_hash(struct doca_ft_key *key)
{
    uint32_t hash = 0;
    if(!key){
        return 0;
    }
    hash = rte_hash_crc_4byte(key->ipv4_1, hash);
    hash = rte_hash_crc_2byte(key->port_1, hash);
    hash = rte_hash_crc_4byte(key->ipv4_2, hash);
    hash = rte_hash_crc_2byte(key->port_2, hash);
    hash = rte_hash_crc_1byte(key->protocol, hash);

    return hash;
}

struct doca_ft *doca_ft_create(int size, uint32_t user_data_size, 
                               void (*gw_aging_cb)(struct doca_ft_user_ctx *ctx),
                               void (*gw_aging_hw_cb)(void))
{
    struct doca_gauge_cfg gauge_cfg = {20,1000};
    struct doca_ft *ft;
    uint32_t act_size;
    uint32_t alloc_size;
    uint32_t i;

    if (size <= 0)
            return NULL;
    /* Align to the next power of 2, 32bits integer is enough now. */
    if (!rte_is_power_of_2(size)) {
            act_size = rte_align32pow2(size);
    } else {
            act_size = size;
    }
    alloc_size = sizeof(struct doca_ft) +
		     sizeof(struct  doca_ft_bucket) * act_size;
   DOCA_LOG_DBG("alloc size =%d",alloc_size);

    ft = malloc(alloc_size*2);
    memset(ft, 0 , alloc_size);
    if (ft == NULL) {
        DOCA_LOG_CRIT("no mem");
        return NULL;
    }

    ft->cfg.entry_size = sizeof(struct doca_ft_entry) + user_data_size;
    ft->cfg.user_data_size = user_data_size;
    ft->cfg.size = act_size;
    ft->cfg.mask = act_size - 1;
    ft->gw_aging_cb = gw_aging_cb;
    ft->gw_aging_hw_cb =gw_aging_hw_cb;
    ft->cps_gauge = doca_gauge_init(&gauge_cfg); 
        
    DOCA_LOG_DBG("FT create size=%d, user_data_size=%d",size, user_data_size);

    for( i = 0 ; i < ft->cfg.size ; i++){
        rte_spinlock_init(&ft->buckets[i].lock);
    }
    doca_ft_aging_thread_start(ft);
    return ft;
}

static
struct doca_ft_entry *_doca_ft_find(struct doca_ft *ft, struct doca_ft_key *key)
{
    uint32_t hash;
    uint32_t idx;
    struct doca_ft_entry_head *first;
    struct doca_ft_entry *node;

    hash = doca_ft_key_hash(key);
    idx = hash & ft->cfg.mask;
    DOCA_LOG_DBG("looking for index%d",idx);
    first = &ft->buckets[idx].head;
    LIST_FOREACH(node, first, next) {
        if (doca_ft_key_equal(&node->key, key)){
            doca_ft_update_expiration(node);
            return node;
        }
    }
    return NULL;
}

bool doca_ft_find(struct doca_ft *ft, struct doca_pkt_info *pinfo, 
                                 struct doca_ft_user_ctx **ctx)
{
    struct doca_ft_entry *fe;
    struct doca_ft_key key = {0};
    if (doca_ft_key_fill(pinfo, &key))
        return false;

    fe = _doca_ft_find(ft, &key);
    if (fe == NULL )
        return false;

    *ctx = &fe->user_ctx;    
    return true; 
}



bool doca_ft_add_new(struct doca_ft *ft, struct doca_pkt_info *pinfo,struct doca_ft_user_ctx **ctx)
{
    uint32_t hash;
    int idx;
    struct doca_ft_key key = {0};
    struct doca_ft_entry *new_e;
    struct doca_ft_entry_head *first;

    if(!ft){
        return false;
    }

    if (doca_ft_key_fill(pinfo, &key)){
        DOCA_LOG_DBG("failed on key");
       return false;
    }

    new_e = malloc(ft->cfg.entry_size);
    if (new_e == NULL) {
        DOCA_LOG_WARN("oom");
        return false;
    }

    memset(new_e,0,ft->cfg.entry_size);
    doca_ft_update_expiration(new_e);
    new_e->user_ctx.fid = ft->fid_ctr++;
    *ctx = &new_e->user_ctx;

    DOCA_LOG_DBG("defined new flow %llu", (unsigned int long long)new_e->user_ctx.fid);
    memcpy(&new_e->key, &key, sizeof(struct doca_ft_key));
    hash = doca_ft_key_hash(&key);
    idx = hash & ft->cfg.mask;
    first = &ft->buckets[idx].head;

    rte_spinlock_lock(&ft->buckets[idx].lock);
    LIST_INSERT_HEAD(first, new_e, next);
    rte_spinlock_unlock(&ft->buckets[idx].lock);
    ft->stats.add++;

    doca_gauge_add_sample(ft->cps_gauge, 1);
    return true;
}


static 
int _doca_ft_destory_flow(struct doca_ft *ft, struct doca_ft_key *key)
{
    struct doca_ft_entry *f;
    if(!key || !ft){
        return -1;
    }

    f = _doca_ft_find(ft, key);

    if(f){
	LIST_REMOVE(f, next);
        ft->gw_aging_cb(&f->user_ctx);
        free(f);
        ft->stats.rm++;
    }
    return 0;
}


int
doca_ft_destory_flow(struct doca_ft *ft, struct doca_ft_key *key)
{
    return _doca_ft_destory_flow(ft,key);
}

void doca_ft_destroy(struct doca_ft *ft)
{
    uint32_t i; 
    struct doca_ft_entry_head *first;
    struct doca_ft_entry *node;

    ft->stop_aging_thread = true;
    for (i = 0 ; i < ft->cfg.size ; i++) {
        do {
            first = &ft->buckets[i].head;
            LIST_FOREACH(node, first, next) {
                LIST_REMOVE(node, next);
                _doca_ft_destory_flow(ft, &node->key);
                continue; 
            }
        } while (0);
    }
    free(ft);
}
