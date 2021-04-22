#include "doca_kpi.h"
#include "doca_gw.h"
#include "doca_log.h"

void doca_pipeline_kpi_get(__doca_unused struct doca_gw_pipeline *pl,
			   __doca_unused struct doca_pipeline_kpi *kpi)
{
	*kpi = *kpi;
}
