#ifndef _GW_H_
#define _GW_H_

#include <stdint.h>
#include <stdbool.h>
#include "doca_flow.h"
#include "doca_pkt.h"

struct gw_port_cfg {
	uint16_t port_id;
	uint16_t nb_desc;
	uint16_t n_queues;
	uint16_t n_hairpinqs;
};

/**
 * @brief - put packet format as readble string.
 *  for debug/log purpose
 *
 * @param pinfo
 * @param str    - pointer to preallocated string
 * @param len    - len of the string
 *
 * @return -1 on fail or str len on success
 */
int gw_parse_pkt_str(struct doca_pkt_info *pinfo, char *str, int len);

/**
 * @brief - overlay to underlay pipeline.
 *  match on:
 *            outer dst_ip/vni
 *            inner 5-tuple
 *
 *  modify:
 *            decap
 *            inner-dst ip
 *
 *            count
 *            meter
 *
 *  fwd:      RSS-table
 *
 * @param p
 *
 * @return
 */
struct doca_flow_pipeline *gw_init_ol_to_ul_pipeline(struct doca_flow_port *p);

/**
 * @brief - overlay to overlay pipeline
 *
 *  match on:
 *            outer dst_ip/vni
 *            inner 5-tuple
 *
 *  modify:
 *            decap
 *            inner-dst ip
 *            encap
 *
 *            count
 *            meter
 *
 *  fwd:      port
 *
 *
 * @return
 */
struct doca_flow_pipeline *gw_init_ol_to_ol_pipeline(struct doca_flow_port *p);

/**
 * @brief - init doca port matching the provided configiration.
 *
 * @param port_cfg
 *
 * @return
 */
struct doca_flow_port *gw_init_doca_port(struct gw_port_cfg *port_cfg);

enum gw_classification {
	GW_CLS_OL_TO_UL,
	GW_CLS_OL_TO_OL,
	GW_BYPASS_L4,
	GW_BYPASS,
};

/**
 * @brief - decides about the type of the packet.
 *  which pipeline should be exeuted
 *
 * @param pinfo
 *
 * @return
 */
enum gw_classification gw_classifiy_pkt(struct doca_pkt_info *pinfo);

/**
 * @brief - configure entry in the overlay to underlay pipeline
 *
 * @param pinfo
 * @param pipeline
 *
 * @return handle
 */
struct doca_flow_pipeline_entry *
gw_pipeline_add_ol_to_ul_entry(struct doca_pkt_info *pinfo,
			       struct doca_flow_pipeline *pipeline);

/**
 * @brief
 *
 * @param pinfo
 * @param pipeline
 *
 * @return
 */
struct doca_flow_pipeline_entry *
gw_pipeline_add_ol_to_ol_entry(struct doca_pkt_info *pinfo,
			       struct doca_flow_pipeline *pipeline);

void gw_rm_pipeline_entry(struct doca_flow_pipeline_entry *entry);

struct doca_vnf *gw_get_doca_vnf(void);

#endif
