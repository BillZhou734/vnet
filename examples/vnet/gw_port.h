#ifndef _GW_PORT_H_
#define _GW_PORT_H_

int gw_init_port(int port_id, int nr_queues);
void gw_close_port(int port_id);
void gw_dump_port_stats(uint16_t port_id);
#endif
