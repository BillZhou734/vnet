#include <string.h>
#include "doca_kpi.h"
#include "doca_log.h"

#include "rte_cycles.h"

#define PUI64 (unsigned int long long)

DOCA_LOG_MODULE(KPI)

struct doca_gauge_bin {
        uint64_t sum;
        uint64_t n;
};

struct _doca_gauge_cfg {
        int	 n_bins;
        int	 bin_time;
	uint32_t total_time;  // window total size in msec
};

struct doca_gauge {


	struct _doca_gauge_cfg cfg;

        uint8_t curr_bin_idx;
        uint64_t next_bin_time;
        
        /* gauges */
        struct doca_gauge_bin sum_of_samples;  
        struct doca_gauge_bin peak_sum_of_samples;
        struct doca_gauge_bin total; /* total over all time */

	// array of traffic counters. the bin used to compute the rate
        struct doca_gauge_bin bin[0];
};

static uint64_t doca_gauge_msec_to_cycles(int msec)
{
    return msec* rte_get_timer_hz()/1000;
}

static uint64_t doca_get_current_time(void)
{
    return rte_rdtsc();
}

static inline uint64_t doca_gauge_next_time(struct doca_gauge *gauge)
{
    return gauge->cfg.bin_time * rte_get_timer_hz()/1000;
}

static inline void doca_gauge_zero_gauge(struct doca_gauge * gauge)
{
        /* all time total */
        gauge->total.sum   += gauge->bin[gauge->curr_bin_idx].sum;
        gauge->total.n += gauge->bin[gauge->curr_bin_idx].n;

        gauge->curr_bin_idx = 0;
        gauge->next_bin_time = doca_get_current_time() + doca_gauge_next_time(gauge);
        gauge->sum_of_samples.sum = 0;
        gauge->sum_of_samples.n = 0;
	memset(gauge->bin,0,sizeof(struct doca_gauge_bin) * gauge->cfg.n_bins);
}

struct doca_gauge * doca_gauge_init(struct doca_gauge_cfg * cfg)
{
	struct doca_gauge * ret;
        int alloc_size = sizeof(struct doca_gauge) + 
                                    (cfg->n_bins+1)*sizeof(struct doca_gauge_bin);

	ret = (struct doca_gauge *) malloc(alloc_size);
	if (ret == NULL)
		return NULL;

        memset(ret,0,alloc_size);
	ret->cfg.n_bins = cfg->n_bins + 1;
        ret->cfg.total_time = doca_gauge_msec_to_cycles(cfg->time);
	ret->cfg.bin_time = cfg->time / (cfg->n_bins);

        doca_gauge_zero_gauge(ret);
        DOCA_LOG_INFO("created gauge bins[%d], bin_time[%d], total[%d]",ret->cfg.n_bins, ret->cfg.bin_time, ret->cfg.total_time);

	return ret;
}

/**
 * check if the gauge value array index needs to be advanced and advance it if needed.
 * this happens if the current time (jiffies) in the system indicates that the current slot
 * is old by more then the sampling inteval.
 */
static inline void doca_gauge_check_advance(struct doca_gauge * gauge)
{
        uint64_t now = doca_get_current_time();

        if (now <= gauge->next_bin_time)
                return;

        DOCA_LOG_DBG("gauge advance needed. now %llu next_time_slot %llu", now, gauge->next_bin_time);

        /* need to zero all bins at once in this case */
        if (now - gauge->next_bin_time > gauge->cfg.total_time) {
            doca_gauge_zero_gauge(gauge); 
            return;
        }

        while (now > gauge->next_bin_time) {
                uint8_t next;

                DOCA_LOG_DBG("advancing current %u current_time %llu total bytes %llu pkts %llu now %llu",
                             gauge->curr_bin_idx, gauge->next_bin_time, gauge->total.sum, gauge->total.n, now);
                next = (gauge->curr_bin_idx + 1) % gauge->cfg.n_bins;
                gauge->sum_of_samples.sum   += gauge->bin[gauge->curr_bin_idx].sum - gauge->bin[next].sum;
                gauge->sum_of_samples.n += gauge->bin[gauge->curr_bin_idx].n - gauge->bin[next].n;
                gauge->total.sum   += gauge->bin[gauge->curr_bin_idx].sum;
                gauge->total.n += gauge->bin[gauge->curr_bin_idx].n;

                if (gauge->sum_of_samples.sum > gauge->peak_sum_of_samples.sum) {
                        gauge->peak_sum_of_samples.sum = gauge->sum_of_samples.sum;
                }

                if (gauge->sum_of_samples.n > gauge->peak_sum_of_samples.n) {
                        gauge->peak_sum_of_samples.n = gauge->sum_of_samples.n;
                }

                gauge->bin[next].sum = 0;
                gauge->bin[next].n = 0;
                gauge->curr_bin_idx = next;
                gauge->next_bin_time += doca_gauge_next_time(gauge);
        }
}

void doca_gauge_reset(struct doca_gauge * gauge)
{
        doca_gauge_zero_gauge(gauge); 
        gauge->total.sum = 0;
        gauge->total.n = 0;
        gauge->peak_sum_of_samples.sum = 0;
        gauge->peak_sum_of_samples.n = 0;
}

void doca_gauge_add_sample(struct doca_gauge * gauge, uint32_t count)
{
        DOCA_LOG_DBG("updating gauge. curr slot n %llu sum %llu",
                     gauge->bin[gauge->curr_bin_idx].n, gauge->bin[gauge->curr_bin_idx].sum);

        doca_gauge_check_advance(gauge);

        gauge->bin[gauge->curr_bin_idx].n++;
        gauge->bin[gauge->curr_bin_idx].sum += count;
}

void doca_gauge_multi_sample(struct doca_gauge * gauge, uint32_t count, uint32_t n)
{
        DOCA_LOG_DBG("updating gauge. curr slot n %llu sum %llu",
                     gauge->bin[gauge->curr_bin_idx].n, gauge->bin[gauge->curr_bin_idx].sum);

        doca_gauge_check_advance(gauge);

        gauge->bin[gauge->curr_bin_idx].n+=n;
        gauge->bin[gauge->curr_bin_idx].sum += count;
}

uint64_t doca_gauge_get_sum(struct doca_gauge * gauge)
{
        doca_gauge_check_advance(gauge);
	return gauge->sum_of_samples.sum;
}

int doca_gauge_get_load(struct doca_gauge * gauge)
{
    doca_gauge_check_advance(gauge);
    return gauge->sum_of_samples.n > 0?(gauge->sum_of_samples.sum * 100)/gauge->sum_of_samples.n:0;
}

int doca_gauge_get_avg(struct doca_gauge * gauge)
{
    doca_gauge_check_advance(gauge);
    return gauge->sum_of_samples.n > 0?(gauge->sum_of_samples.sum)/gauge->sum_of_samples.n:0;
}

int doca_gauge_get_total_avg(struct doca_gauge * gauge) 
{
    doca_gauge_check_advance(gauge);
    return gauge->total.n > 0?(gauge->total.sum) / (gauge->total.n):0;
}

uint64_t doca_gauge_get_total(struct doca_gauge * gauge)
{
    doca_gauge_check_advance(gauge);
    return gauge->total.sum;
}
