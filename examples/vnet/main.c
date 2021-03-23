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

#include "doca_gw.h"
#include "doca_pcap.h"
#include "doca_log.h"
#include "gw.h"
#include "doca_ft.h"
#include "gw_port.h"
#include "doca_vnf.h"

DOCA_LOG_MODULE(main);

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M,uint8_t *)
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)

#define VNF_ENTRY_BUFF_SIZE (128)
#define VNF_RX_BURST_SIZE (32)
#define VNF_NUM_OF_PORTS (2)

static volatile bool force_quit;

uint16_t nr_queues = 8;
static const char *pcap_file_name = "/var/opt/rbaryanai/vnet/build/examples/vnet/test.pcap";
static struct doca_pcap_hander *ph;

static struct doca_vnf *vnf;

struct vnf_per_core_params {
    int ports[VNF_NUM_OF_PORTS];
    int queues[VNF_NUM_OF_PORTS];
    int core_id;
    bool used;
};

struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

static inline uint64_t gw_get_time_usec(void)
{
    //TODO: this is very bad way to do it
    //need to set start time and use rte_
    struct timeval tv;
    gettimeofday(&tv,NULL);

    return tv.tv_sec * 1000000 + tv.tv_usec;
}

static void vnf_adjust_mbuf(struct rte_mbuf *m, struct doca_pkt_info *pinfo)
{
    int diff = pinfo->outer.l2 - VNF_PKT_L2(m);
    if (diff > 0) {
        //rte_pktmbuf_adj(m,diff);
    }
    //rte_pktmbuf_adj(m,diff);
}

static void
doca_xstats_display(int port_id)
{
	struct rte_eth_xstat *xstats;
	int cnt_xstats, idx_xstat;
	struct rte_eth_xstat_name *xstats_names;

	port_id = 0;
	printf("###### NIC extended statistics for port %-2d\n", port_id);
	if (!rte_eth_dev_is_valid_port(port_id)) {
		printf("Error: Invalid port number %i\n", port_id);
		return;
	}

	/* Get count */
	cnt_xstats = rte_eth_xstats_get_names(port_id, NULL, 0);
	if (cnt_xstats  < 0) {
		printf("Error: Cannot get count of xstats\n");
		return;
	}

	/* Get id-name lookup table */
	xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * cnt_xstats);
	if (xstats_names == NULL) {
		printf("Cannot allocate memory for xstats lookup\n");
		return;
	}
	if (cnt_xstats != rte_eth_xstats_get_names(
			port_id, xstats_names, cnt_xstats)) {
		printf("Error: Cannot get xstats lookup\n");
		free(xstats_names);
		return;
	}

	/* Get stats themselves */
	xstats = malloc(sizeof(struct rte_eth_xstat) * cnt_xstats);
	if (xstats == NULL) {
		printf("Cannot allocate memory for xstats\n");
		free(xstats_names);
		return;
	}
	if (cnt_xstats != rte_eth_xstats_get(port_id, xstats, cnt_xstats)) {
		printf("Error: Unable to get xstats\n");
		free(xstats_names);
		free(xstats);
		return;
	}

	/* Display xstats */
	for (idx_xstat = 0; idx_xstat < cnt_xstats; idx_xstat++) {
		if (!xstats[idx_xstat].value)
			continue;
		printf("%s: %"PRIu64"\n",
			xstats_names[idx_xstat].name,
			xstats[idx_xstat].value);
	}
	free(xstats_names);
	free(xstats);
}

static uint64_t doca_timer_period = 1;
#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif
#define NS_PER_SEC 1E9

static void
gw_port_stats_display(uint16_t port_id)
{
	uint32_t i;
	static uint64_t prev_pkts_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_pkts_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_rx[RTE_MAX_ETHPORTS];
	static uint64_t prev_bytes_tx[RTE_MAX_ETHPORTS];
	static uint64_t prev_ns[RTE_MAX_ETHPORTS];
	struct timespec cur_time;
	uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx,
								diff_ns;
	uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
	struct rte_eth_stats stats;

	static const char *nic_stats_border = "########################";

	rte_eth_stats_get(port_id, &stats);
	printf("\n  %s NIC statistics for port %-2d %s\n",
	       nic_stats_border, port_id, nic_stats_border);

	printf("  RX-packets: %-10"PRIu64" RX-missed: %-10"PRIu64" RX-bytes:  "
	       "%-"PRIu64"\n", stats.ipackets, stats.imissed, stats.ibytes);
	printf("  RX-errors: %-"PRIu64"\n", stats.ierrors);
	printf("  RX-nombuf:  %-10"PRIu64"\n", stats.rx_nombuf);
	printf("  TX-packets: %-10"PRIu64" TX-errors: %-10"PRIu64" TX-bytes:  "
	       "%-"PRIu64"\n", stats.opackets, stats.oerrors, stats.obytes);

	printf("\n");
	for (i = 0; i < nr_queues; i++) {
		printf("  Stats reg %2d RX-packets: %-10"PRIu64
		       "  RX-errors: %-10"PRIu64
		       "  RX-bytes: %-10"PRIu64"\n",
		       i, stats.q_ipackets[i], stats.q_errors[i], stats.q_ibytes[i]);
	}

	printf("\n");
	for (i = 0; i < nr_queues; i++) {
		printf("  Stats reg %2d TX-packets: %-10"PRIu64
		       "  TX-bytes: %-10"PRIu64"\n",
		       i, stats.q_opackets[i], stats.q_obytes[i]);
	}	

	diff_ns = 0;
	if (clock_gettime(CLOCK_TYPE_ID, &cur_time) == 0) {
		uint64_t ns;

		ns = cur_time.tv_sec * NS_PER_SEC;
		ns += cur_time.tv_nsec;

		if (prev_ns[port_id] != 0)
			diff_ns = ns - prev_ns[port_id];
		prev_ns[port_id] = ns;
	}

	diff_pkts_rx = (stats.ipackets > prev_pkts_rx[port_id]) ?
		(stats.ipackets - prev_pkts_rx[port_id]) : 0;
	diff_pkts_tx = (stats.opackets > prev_pkts_tx[port_id]) ?
		(stats.opackets - prev_pkts_tx[port_id]) : 0;
	prev_pkts_rx[port_id] = stats.ipackets;
	prev_pkts_tx[port_id] = stats.opackets;
	mpps_rx = diff_ns > 0 ?
		(double)diff_pkts_rx / diff_ns * NS_PER_SEC : 0;
	mpps_tx = diff_ns > 0 ?
		(double)diff_pkts_tx / diff_ns * NS_PER_SEC : 0;

	diff_bytes_rx = (stats.ibytes > prev_bytes_rx[port_id]) ?
		(stats.ibytes - prev_bytes_rx[port_id]) : 0;
	diff_bytes_tx = (stats.obytes > prev_bytes_tx[port_id]) ?
		(stats.obytes - prev_bytes_tx[port_id]) : 0;
	prev_bytes_rx[port_id] = stats.ibytes;
	prev_bytes_tx[port_id] = stats.obytes;
	mbps_rx = diff_ns > 0 ?
		(double)diff_bytes_rx / diff_ns * NS_PER_SEC : 0;
	mbps_tx = diff_ns > 0 ?
		(double)diff_bytes_tx / diff_ns * NS_PER_SEC : 0;

	printf("\n  Throughput (since last show)\n");
	printf("  Rx-pps: %12"PRIu64"          Rx-bps: %12"PRIu64"\n  Tx-pps: %12"
	       PRIu64"          Tx-bps: %12"PRIu64"\n", mpps_rx, mbps_rx * 8,
	       mpps_tx, mbps_tx * 8);

	printf("  %s############################%s\n",
	       nic_stats_border, nic_stats_border);
}

static void gw_dump_stats(uint16_t port_id)
{
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

	printf("%s%s", clr, topLeft);
	doca_gw_dump(port_id);
	gw_port_stats_display(port_id);
	fflush(stdout);
}

static int
gw_process_pkts(void *p)
{
	static uint64_t cur_tsc,last_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
	unsigned core_id = rte_lcore_id();
        struct doca_pkt_info pinfo;
        struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;
        int port_id;

	printf("start core:%u\n", core_id);
	last_tsc = rte_rdtsc();
	while (!force_quit) {
		if (core_id == 0) {
			cur_tsc = rte_rdtsc();
			if (cur_tsc > last_tsc + doca_timer_period) {
				gw_dump_stats(0);
				last_tsc = cur_tsc;
			}
		}
            for (port_id = 0; port_id < 2; port_id++) { 
                for (i = 0; i < 1/*nr_queues*/; i++) {
                    nb_rx = rte_eth_rx_burst(port_id, params->queues[port_id], mbufs, VNF_RX_BURST_SIZE);
                    if (nb_rx) {
                        for (j = 0; j < nb_rx; j++) {
                            memset(&pinfo,0, sizeof(struct doca_pkt_info));
							pinfo.orig_data = mbufs[j];
                            if(!doca_parse_packet(VNF_PKT_L2(mbufs[j]),VNF_PKT_LEN(mbufs[j]), &pinfo)){
                                pinfo.orig_port_id = mbufs[j]->port;
                                if (pinfo.outer.l3_type == 4) {
                                    vnf->doca_vnf_process_pkt(&pinfo);
                                    if(ph) {
                                        doca_pcap_write(ph,pinfo.outer.l2, pinfo.len, gw_get_time_usec(), 0); 
                                    }
                                    vnf_adjust_mbuf(mbufs[j], &pinfo);
                                }
                            }
                            rte_eth_tx_burst((mbufs[j]->port == 0) ? 1 : 0, params->queues[port_id], &mbufs[j], 1);
                        }
                    }
                }
            }
	}

        return 0;
}

static void
signal_handler(int signum)
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

static int 
count_lcores(void)
{
    int cores = 0;
    while (core_params_arr[cores].used)
        cores++;
    return cores;
}

#define MAX_LONG_OPT_SZ 64

/**< display usage */
static void
gw_info_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK\n"
		"  --debug: enable debug print\n",
		prgname);
}

static int
gw_parse_uint32(const char *uint32_value)
{
	char *end = NULL;
	uint32_t value;

	value = strtoul(uint32_value, &end, 16);
	if ((uint32_value[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return value;
}


/* Parse the argument given in the command line of the application */
static int
gw_info_parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char *prgname = argv[0];
	uint32_t log_level = 0;
	static struct option long_option[] = {
		{"debug_level", 1, NULL, 0},
		{"stats_timer", 1, NULL, 1},
		{NULL, 0, 0, 0}
	};

	if (argc == 1) {
		gw_info_usage(prgname);
		return -1;
	}
	while ((opt = getopt_long(argc, argv, "",
			long_option, &option_index)) != EOF) {
		switch (opt) {
		case 0:
			log_level = gw_parse_uint32(optarg);
			printf("set debug_level:%u\n", log_level);
			doca_set_log_level(log_level);
			break;
		case 1:
			doca_timer_period = gw_parse_uint32(optarg);
			printf("set stats_timer:%u\n", doca_timer_period);
			break;
		default:
			gw_info_usage(prgname);
			return -1;
		}
	}
	return 0;
}

static void dump_input_argv(int argc, char **argv)
{
	int i;

	for(i = 0; i < argc ; i++)
		printf("argv[%d],%p,%s\n",i, &argv[i], argv[i]);
}
static int
init_dpdk(int argc, char **argv)
{
	int i, ret, total_cores = 0;
	uint16_t nr_ports;

	printf("init_dpdk start...\n");
	dump_input_argv(argc, argv);
	
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		DOCA_LOG_CRIT("invalid EAL arguments\n");
		return ret;
	}
	printf("after parse1...\n");
	dump_input_argv(argc, argv);
	
	argc -= ret;
	argv += ret;

	printf("after parse2...\n");
	dump_input_argv(argc, argv);
	
	gw_info_parse_args(argc, argv);


	memset(core_params_arr, 0, sizeof(core_params_arr));
    for ( i = 0 ; i < nr_queues ; i++) {
        if (rte_lcore_is_enabled(i)){
            core_params_arr[total_cores].ports[0]= 0;
            core_params_arr[total_cores].ports[1]= 1;
            core_params_arr[total_cores].queues[0]= total_cores;
            core_params_arr[total_cores].queues[1]= total_cores;
            core_params_arr[total_cores].core_id = i;
            core_params_arr[total_cores].used = true;
            total_cores++;
        }
    }



        nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0) {
		DOCA_LOG_CRIT("no Ethernet ports found\n");
                return -1;
        }
	
        force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

        return 0;
}

static bool capture_en = 0;

int
main(int argc, char **argv)
{
	int total_cores;
	int i = 0;

	//signal(11, doca_xstats_display);
	if (init_dpdk(argc , argv)) {
		rte_exit(EXIT_FAILURE, "Cannot init dpdk\n");
		return -1;
	}

	doca_timer_period *= rte_get_timer_hz();
	total_cores = nr_queues;//count_lcores();
	DOCA_LOG_INFO("init ports: lcores = %d\n",total_cores);

	gw_init_port(0, total_cores);
	gw_init_port(1, total_cores);

	vnf = gw_get_doca_vnf();
	vnf->doca_vnf_init((void *)&total_cores);

	DOCA_LOG_INFO("VNF initiated!\n");

	if (capture_en) {
		ph = doca_pcap_file_start(pcap_file_name);
	}

	i = 1;
	while (core_params_arr[i].used) {
		rte_eal_remote_launch((lcore_function_t *)gw_process_pkts, 
			&core_params_arr[i], core_params_arr[i].core_id);
		i++;
	}

	// use main lcode as a thread.
	gw_process_pkts(&core_params_arr[i]);

	vnf->doca_vnf_destroy();

	gw_close_port(0);
	gw_close_port(1);

	return 0;
}
