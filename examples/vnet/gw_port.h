#ifndef _GW_PORT_H_
#define _GW_PORT_H_

#include "doca_pkt.h"
#include "gw.h"

int gw_start_dpdk_port(struct gw_port_cfg *port);
void gw_close_port(int port_id);
void gw_dump_port_stats(uint16_t port_id);
#endif
