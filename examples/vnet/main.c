#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>

#include "doca_flow.h"
#include "doca_pcap.h"
#include "doca_log.h"
#include "doca_debug_dpdk.h"
#include "gw.h"
#include "doca_ft.h"
#include "gw_port.h"
#include "doca_vnf.h"

DOCA_LOG_MODULE(main);

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M, uint8_t *)
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)

#define VNF_ENTRY_BUFF_SIZE (128)
#define VNF_RX_BURST_SIZE (32)
#define VNF_NUM_OF_PORTS (2)

static volatile bool force_quit;

uint16_t nr_queues = 4;
uint16_t nr_hairpinq = 0;
uint16_t rx_only = 0;
uint16_t hw_offload = 1;
uint64_t stats_timer = 1;

static const char *pcap_file_name =
	"/var/opt/rbaryanai/vnet/build/examples/vnet/test.pcap";
static struct doca_vnf *vnf;
static struct doca_pcap_hander *ph;

struct vnf_per_core_params {
	int ports[VNF_NUM_OF_PORTS];
	int queues[VNF_NUM_OF_PORTS];
	int core_id;
	bool used;
};
struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

/*this is very bad way to do it, need to set start time and use rte_*/
static inline uint64_t gw_get_time_usec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

static void vnf_adjust_mbuf(struct rte_mbuf *m, struct doca_pkt_info *pinfo)
{
	int diff = pinfo->outer.l2 - VNF_PKT_L2(m);

	return;
	rte_pktmbuf_adj(m, diff);
}

static void gw_process_offload(struct rte_mbuf *mbuf)
{
	struct doca_pkt_info pinfo;

	memset(&pinfo, 0, sizeof(struct doca_pkt_info));
	if (doca_parse_packet(VNF_PKT_L2(mbuf), VNF_PKT_LEN(mbuf), &pinfo))
		return;
	pinfo.orig_data = mbuf;
	pinfo.orig_port_id = mbuf->port;
	pinfo.rss_hash = mbuf->hash.rss;
	if (pinfo.outer.l3_type != GW_IPV4)
		return;
	vnf->doca_vnf_process_pkt(&pinfo);
	if (ph)
		doca_pcap_write(ph, pinfo.outer.l2, pinfo.len,
				gw_get_time_usec(), 0);
	vnf_adjust_mbuf(mbuf, &pinfo);
}

static int gw_process_pkts(void *p)
{
	uint64_t cur_tsc, last_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx, queue_id;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;

	DOCA_LOG_INFO("core %u process queue %u start", core_id,
		      params->queues[port_id]);
	last_tsc = rte_rdtsc();
	while (!force_quit) {
		if (core_id == 0) {
			cur_tsc = rte_rdtsc();
			if (cur_tsc > last_tsc + stats_timer) {
				gw_dump_port_stats(0);
				last_tsc = cur_tsc;
			}
		}
		for (port_id = 0; port_id < 2; port_id++) {
			queue_id = params->queues[port_id];
			nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs,
						 VNF_RX_BURST_SIZE);
			for (j = 0; j < nb_rx; j++) {
				if (hw_offload)
					gw_process_offload(mbufs[j]);
				if (rx_only)
					rte_pktmbuf_free(mbufs[j]);
				else
					rte_eth_tx_burst(port_id == 0 ? 1 : 0,
							 queue_id, &mbufs[j],
							 1);
			}
		}
	}
	return 0;
}

static void signal_handler(int signum)
{
	if (ph != NULL) {
		doca_pcap_file_stop(ph);
		ph = NULL;
	}

	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
		       signum);
		force_quit = true;
	}
}

static int count_lcores(void)
{
	int cores = 0;

	while (core_params_arr[cores].used)
		cores++;
	return cores;
}

static void gw_info_usage(const char *prgname)
{
	printf("%s [EAL options] -- \n"
	       "  --log_level: set log level\n"
	       "  --stats_timer: set interval to dump stats information\n"
	       "  --nr_queues: set queues number\n"
	       "  --nr_hairpinq: set haripin queues number\n"
	       "  --rx_only: set rx_only 0 or 1\n"
	       "  --hw_offload: set hw offload 0 or 1\n",
	       prgname);
}

static int gw_parse_uint32(const char *uint32_value)
{
	char *end = NULL;
	uint32_t value;

	value = strtoul(uint32_value, &end, 10);
	if ((uint32_value[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	return value;
}

static int gw_info_parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char *prgname = argv[0];
	uint32_t log_level = 0;
	static struct option long_option[] = {
		{"log_level", 1, NULL, 0},
		{"stats_timer", 1, NULL, 1},
		{"nr_queues", 1, NULL, 2},
		{"rx_only", 1, NULL, 3},
		{"hw_offload", 1, NULL, 4},
		{"nr_hairpinq", 1, NULL, 5},
		{NULL, 0, 0, 0},
	};

	if (argc == 1) {
		gw_info_usage(prgname);
		return -1;
	}
	while ((opt = getopt_long(argc, argv, "", long_option,
				  &option_index)) != EOF) {
		switch (opt) {
		case 0:
			log_level = gw_parse_uint32(optarg);
			printf("set debug_level:%u\n", log_level);
			doca_set_log_level(log_level);
			break;
		case 1:
			stats_timer = gw_parse_uint32(optarg);
			printf("set stats_timer:%lu\n", stats_timer);
			break;
		case 2:
			nr_queues = gw_parse_uint32(optarg);
			if (nr_queues > 16) {
				printf("nr_queues should be 2 - 16\n");
				return -1;
			}
			printf("set nr_queues:%u.\n", nr_queues);
			break;
		case 3:
			rx_only = gw_parse_uint32(optarg);
			printf("set rx_only:%u.\n", rx_only == 0 ? 0 : 1);
			break;
		case 4:
			hw_offload = gw_parse_uint32(optarg);
			printf("set hw_offload:%u.\n", hw_offload == 0 ? 0 : 1);
			break;
		case 5:
			nr_hairpinq = gw_parse_uint32(optarg);
			if (nr_hairpinq > 1) {
				printf("only support one haripin queue\n");
				nr_hairpinq = 1;
			}
			printf("set nr_hairpinq:%u.\n", nr_hairpinq);
			break;

		default:
			gw_info_usage(prgname);
			return -1;
		}
	}
	return 0;
}
static int init_dpdk(int argc, char **argv)
{
	int i, ret, core_idx = 0;
	uint16_t nr_ports;

	memset(core_params_arr, 0, sizeof(core_params_arr));
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		DOCA_LOG_CRIT("invalid EAL arguments\n");
		return ret;
	}
	argc -= ret;
	argv += ret;
	gw_info_parse_args(argc, argv);

	for (i = 0; i < nr_queues; i++) {
		if (rte_lcore_is_enabled(i)) {
			core_params_arr[core_idx].ports[0] = 0;
			core_params_arr[core_idx].ports[1] = 1;
			core_params_arr[core_idx].queues[0] = core_idx;
			core_params_arr[core_idx].queues[1] = core_idx;
			core_params_arr[core_idx].core_id = i;
			core_params_arr[core_idx].used = true;
			core_idx++;
		}
	}
	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0) {
		DOCA_LOG_CRIT("no Ethernet ports found\n");
		return -1;
	}
	stats_timer *= rte_get_timer_hz();
	if (nr_queues > count_lcores())
		nr_queues = count_lcores();
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	return 0;
}

static bool capture_en = 0;

int main(int argc, char **argv)
{
	int i = 0;
	uint16_t port_id;
	struct gw_port_cfg port_cfg = {0};

	if (init_dpdk(argc, argv)) {
		rte_exit(EXIT_FAILURE, "Cannot init dpdk\n");
		return -1;
	}

	port_cfg.n_queues = nr_queues;
	port_cfg.n_hairpinqs = nr_hairpinq;
	RTE_ETH_FOREACH_DEV(port_id) {
		port_cfg.port_id = port_id;
		gw_start_dpdk_port(&port_cfg);
	}

	vnf = gw_get_doca_vnf();
	vnf->doca_vnf_init((void *)&port_cfg);
	DOCA_LOG_INFO("VNF initiated!\n");
	if (capture_en)
		ph = doca_pcap_file_start(pcap_file_name);
	i = 1;
	while (core_params_arr[i].used) {
		rte_eal_remote_launch((lcore_function_t *)gw_process_pkts,
				      &core_params_arr[i],
				      core_params_arr[i].core_id);
		i++;
	}

	/* use main lcode as a thread.*/
	gw_process_pkts(&core_params_arr[i]);
	vnf->doca_vnf_destroy();

	RTE_ETH_FOREACH_DEV(port_id)
		gw_close_port(port_id);
	return 0;
}
