#ifndef _DOCA_VNF_H_
#define _DOCA_VNF_H_

#include <stdint.h>

struct doca_pkt_info;

struct doca_vnf {
	int (*doca_vnf_init)(void *p);
	int (*doca_vnf_process_pkt)(struct doca_pkt_info *pinfo);
	int (*doca_vnf_destroy)(void);
};

#endif
