#ifndef _DOCA_GAUGE_H_
#define _DOCA_GAUGE_H_

#include <stdint.h>
/*
 * Siliding window gauge.
 * gauge is defined by number of bins and total sampled time.
 * more bins means less burstiness but more calculations.
 *
 * The samples are built from count and n, where n is the number
 * of samples added, and count is the samples total value added,
 * when adding only count it means n = 1, in this case.
 *
 * for throughput count = packet size.
 * the rate/sec is the average count per second, or if gauge
 * is defined as a second window, then the sum of count.
 *
 */

struct doca_gauge;
struct doca_cycles_gauge;

struct doca_gauge_cfg {
	int n_bins; /* num of bins for sliding window */
	int time;   /* total gauge time in msec */
};

/**
 * @brief - allocate new gauge
 *
 * @param cfg
 *
 * @return
 */
struct doca_gauge *doca_gauge_init(struct doca_gauge_cfg *cfg);

/**
 * @brief - reset to inital state (like new alloc)
 *
 * @param gauge
 */
void doca_gauge_reset(struct doca_gauge *gauge);

/**
 * @brief - add a count to current bin
 *
 * @param gauge
 * @param count   - value of the sample
 */
void doca_gauge_add_sample(struct doca_gauge *gauge, uint32_t count);

void doca_gauge_multi_sample(struct doca_gauge *gauge, uint32_t count,
			     uint32_t n);

uint64_t doca_gauge_get_sum(struct doca_gauge *gauge);

int doca_gauge_get_load(struct doca_gauge *gauge);

int doca_gauge_get_avg(struct doca_gauge *gauge);

int doca_gauge_get_total_avg(struct doca_gauge *gauge);

uint64_t doca_gauge_get_total(struct doca_gauge *gauge);

#endif
