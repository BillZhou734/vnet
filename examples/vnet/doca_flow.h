/**
 * @brief
 *
 * GW has the following pipe
 *
 * match:    modify    -->
 * - outer   - decap
 * - tunnel  - headers (ip..etc)
 * - inner   - encap
 *
 *   --> monitor       -->
 *      - count (per session)
 *      - meter
 *      - mirror
 *
 *  FWD
 *    - SW (queue RSS)
 *    - Port
 *      - load balance
 *      - ecmp
 *      - FIB
 *
 * Pipeline is a subset of the generic pipe where
 * none relevant fields are masked out, constant fields are
 * given a single value.
 *
 * Pipeline can support:
 *    - meter (entire traffic on pipe)
 *    - count
 *
 * Once a pipe is defined (attached to port), pipe
 * can be populated by entries, where only none masked/none constant
 * fields are provided.
 *
 * Support:
 *  - aging
 *  - offload KPI's
 */
#ifndef _DOCA_FLOW_H_
#define _DOCA_FLOW_H_

#include <stdint.h>
#include <stdbool.h>
#include "doca_net.h"

struct doca_flow_port;
struct doca_flow_pipe;
struct doca_flow_pipe_entry;

/**
 * @brief :
 *    API calls failure reasons
 */
enum doca_flow_error_type {
	DOCA_ERROR_UNKNOWN,
	DOCA_ERROR_UNSUPPORTED,
	DOCA_ERROR_TABLE_IS_FULL,
	DOCA_ERROR_NOMORE_PIPE_RESOURCE,
	DOCA_ERROR_PIPE_BUILD_IMTE_ERROR,
	DOCA_ERROR_PIPE_BUILD_ACTION_ERROR,
	DOCA_ERROR_OOM,
};

/**
 * @brief - each call to api include error message struct.
 *  in case of an error, error type and a description of the error
 *  is provided.
 */
struct doca_flow_error {
	enum doca_flow_error_type type;
	const char *message;
};

/**
 * @brief - flow global configurations
 */
struct doca_flow_cfg {
	uint32_t total_sessions;
	uint16_t
	    queues; /* each offload thread should use a different queue id */
	bool aging; /* when true, aging is handled by doca */
};

enum doca_flow_port_type {
	DOCA_FLOW_PORT_DPDK,
	DOCA_FLOW_PORT_DPDK_BY_ID,
};

struct doca_flow_port_cfg {
	uint16_t port_id;
	enum doca_flow_port_type type; /* mapping type of port */
	uint16_t queues;
	const char *devargs;	 /* specific per port type cfg */
	uint16_t priv_data_size; /* user private data */
};

/**
 * @brief - matcher
 *   - used for defintion of a pipe
 *   - used for adding entry
 *     - only changeable fields are needed
 */
struct doca_flow_match {

	uint8_t out_src_mac[DOCA_ETHER_ADDR_LEN];
	uint8_t out_dst_mac[DOCA_ETHER_ADDR_LEN];
	uint16_t vlan_id;

	/* outer if tunnel exists */
	struct doca_ip_addr out_src_ip;
	struct doca_ip_addr out_dst_ip;
	uint8_t out_l4_type;
	uint16_t out_src_port;
	uint16_t out_dst_port;

	struct doca_flow_tun tun;

	/* exists if tunnel is used */
	struct doca_ip_addr in_src_ip;
	struct doca_ip_addr in_dst_ip;

	uint8_t in_l4_type;
	uint16_t in_src_port;
	uint16_t in_dst_port;
};

struct doca_flow_encap_action {

	uint8_t src_mac[DOCA_ETHER_ADDR_LEN];
	uint8_t dst_mac[DOCA_ETHER_ADDR_LEN];

	struct doca_ip_addr in_src_ip;
	struct doca_ip_addr in_dst_ip;
	struct doca_flow_tun tun;
};

/**
 * @brief - action template
 *    - used for defintion per pipe
 *    - used when adding entries for a pipe
 */
struct doca_flow_actions {

	uint8_t flags;
	bool decap;

	uint8_t mod_src_mac[DOCA_ETHER_ADDR_LEN];
	uint8_t mod_dst_mac[DOCA_ETHER_ADDR_LEN];

	struct doca_ip_addr mod_src_ip;
	struct doca_ip_addr mod_dst_ip;

	uint16_t mod_src_port;
	uint16_t mod_dst_port;

	bool dec_ttl;
	uint32_t tcp_seq_shift;
	uint32_t tcp_ack_shift;

	struct doca_flow_encap_action encap;
};

enum {
	DOCA_FLOW_NONE = 0,
	DOCA_FLOW_METER = (1 << 1),
	DOCA_FLOW_COUNT = (1 << 2),
	DOCA_FLOW_AGING = (1 << 3),
};

enum doca_flow_fwd_type { 
    DOCA_FWD_NONE = 0,
    DOCA_FWD_RSS,
    DOCA_FWD_PORT, 
    DOCA_FWD_PIPE,
};

enum doca_rss_type {
	DOCA_RSS_IP = (1 << 0),
	DOCA_RSS_UDP = (1 << 1),
	DOCA_RSS_TCP = (1 << 2),
};

/**
 * @brief - forwarding configuration
 */
struct doca_flow_fwd {
    enum doca_flow_fwd_type type;
    union {
        struct fwd_rss {
                uint32_t rss_flags;
                uint16_t *queues;
                uint32_t num_queues;
        } rss;

        struct port {
                int id;
			uint16_t hairpinq;
        } port;

        struct next_pipelne {
            struct doca_flow_pipe *next;
        } next_pipe;
    };
};


struct doca_flow_monitor {
	uint8_t flags;
	bool count;
	struct meter {
		uint32_t id;
		uint64_t cir;
		uint64_t cbs;
		struct doca_flow_fwd fwd;
	} m;

	struct mirror {

	} mirror;

	uint32_t aging;
};

/**
 * @brief - pipe definition
 */
struct doca_flow_pipe_cfg {
        struct {
            const char *name;
            bool root; /* when true, first pipe executed on
                          packet arrival */
        };
	struct doca_flow_port *port;
	struct doca_flow_match *match;
	struct doca_flow_match *match_mask;
	struct doca_flow_actions *actions;
	struct doca_flow_monitor *monitor;
	bool count; /* count for entire pipe */
};

struct doca_flow_query {
	uint64_t total_bytes;
	uint64_t total_pkts;
	uint32_t last_used; /* in seconds */
};

/**
 * @brief - create a forwarding table that can be used in pipe.
 *
 *
 * @param cfg
 *
 * @return
 */
//struct doca_flow_fwd_tbl *
//doca_flow_create_fwd_tbl(struct doca_flow_fwd *cfg);

/**
 * @brief
 *      one time call, used for doca flow init and global
 *      configurations.
 *
 * @param cgf
 *
 * @return
 */
int doca_flow_init(struct doca_flow_cfg *cfg, struct doca_flow_error *err);

/**
 * @brief - start a doca port. doca ports are required to define pipes.
 *          ports are also required for forwarding.
 *
 * @param cfg   - port configuration
 * @param err   - on failure will hold failed message
 *
 * @return port instance on success
 */
struct doca_flow_port *doca_flow_port_start(struct doca_flow_port_cfg *cfg,
					    struct doca_flow_error *err);

/**
 * @brief - close port
 *  release all resources used by port, including all HW rules.
 *
 * @param port
 *
 * @return
 */
int doca_flow_port_stop(struct doca_flow_port *port);

/**
 * @brief - return pointer to user private data.
 *   user can manage specific data stucture.
 *   the size of the data structure is given on port cfg
 *
 * @param p
 *
 * @return
 */
uint8_t *doca_flow_port_priv_data(struct doca_flow_port *p);

/**
 * @brief - create new pipe.
 *
 * @param cfg
 * @param err    - err reason and message on failure
 *
 * @return pipe handler or NULL on failure
 */
struct doca_flow_pipe *
doca_flow_create_pipe(struct doca_flow_pipe_cfg *cfg,
                      struct doca_flow_fwd *fwd,
		      struct doca_flow_error *err);

/**
 * @brief
 *
 * @param pipe_queue  - each thread should use a unique id
 * @param pipe
 * @param match
 * @param actions
 * @param mod
 * @param fwd
 * @param err
 *
 * @return entry ref on success and NULL otherwise with reason filled in err.
 */
struct doca_flow_pipe_entry *doca_flow_pipe_add_entry(
	uint16_t pipe_queue, struct doca_flow_pipe *pipe,
	struct doca_flow_match *match, struct doca_flow_actions *actions,
	struct doca_flow_monitor *mod, struct doca_flow_fwd *fwd,
	struct doca_flow_error *err);

/**
 * @brief - default pipe is match all, and send to SW.
 *          RSS on all queues.
 *
 *          Using this flow it is allowed to change this behaviour and define
 *          different RSS behaviour for unmatched packets.
 *
 * @param pipe_queue
 * @param port
 * @param fwd
 * @param err
 *
 * @return 0 on success and error reason for other
 */
int doca_flow_pipe_update_default(uint16_t pipe_queue,
				      struct doca_flow_port *port,
				      struct doca_flow_fwd *fwd,
				      struct doca_flow_error *err);

/**
 * @brief
 *
 * @param match
 *
 * @return
 */
int doca_flow_rm_entry(uint16_t pipe_queue,
		       struct doca_flow_pipe_entry *entry);

/**
 * @brief - extract information about specific entry
 *
 * @param pe - entry handler
 * @param q  - information will be placed here
 *
 * @return 0 on success
 */
int doca_flow_query(struct doca_flow_pipe_entry *pe,
		    struct doca_flow_query *q);

/**
 * @brief
 *    when aging is handled by doca, the following function should
 *    be returned
 *
 * @param arr       - aged out flows are put here
 * @param arr_len   - length of the array
 * @param n         - number of entries filled (ready to be aged out entries)
 *
 * @return true if there are more waiting entries for aging.
 */
bool doca_flow_query_aging(struct doca_flow_pipe_entry *arr, int arr_len,
			   int *n);

void doca_flow_destroy(uint16_t port_id);
void doca_flow_dump_pipe(uint16_t port_id);

//struct doca_flow_fwd *doca_flow_fwd_cast(struct doca_flow_fwd_tbl *tbl);
#endif
