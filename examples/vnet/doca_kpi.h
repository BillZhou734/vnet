#ifndef _DOCA_KPI_H_
#define _DOCA_KPI_H_

#include <stdint.h>
#include "doca_gauge.h"

struct doca_gw_pipeline;

struct doca_pipeline_kpi {
   uint64_t avg_cycles;
   uint64_t total_cycles;
   uint64_t load;
};

void doca_pipeline_kpi_get(struct doca_gw_pipeline *pl, struct doca_pipeline_kpi *kpi);

#endif
