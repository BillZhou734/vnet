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

uint16_t nr_queues = 4;
uint16_t nb_desc = 1024;
uint16_t rx_only = 1;
uint16_t no_offload = 0;
uint16_t meter_action = 0;
static bool capture_en = 0;
static uint32_t total_pkts = 0;

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
static uint64_t stats_timer = 1;

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


struct gw_cpu_usage gw_cpu[64];
static void
gw_process_offload(struct rte_mbuf *mbuf)
{
	struct doca_pkt_info pinfo;

    memset(&pinfo,0, sizeof(struct doca_pkt_info));
    if(!doca_parse_packet(VNF_PKT_L2(mbuf),VNF_PKT_LEN(mbuf), &pinfo)){
		pinfo.orig_data = mbuf;
        pinfo.orig_port_id = mbuf->port;
		pinfo.rss_hash = mbuf->hash.rss;
        if (pinfo.outer.l3_type == 4) {
            vnf->doca_vnf_process_pkt(&pinfo);
#if 0
            if(ph) {
                doca_pcap_write(ph,pinfo.outer.l2, pinfo.len, gw_get_time_usec(), 0); 
            }
#endif
            vnf_adjust_mbuf(mbuf, &pinfo);
        }
    }
}

static int
gw_process_pkts(void *p)
{
	uint64_t cur_tsc, last_tsc, delt_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;

	last_tsc = rte_rdtsc();
	memset(&gw_cpu[core_id], 0x0, sizeof(struct gw_cpu_usage));
	rte_atomic64_set(&gw_cpu[core_id].start, last_tsc);
	printf("start core:%u,queueid:%d\n", core_id, params->queues[port_id]);
	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		if (core_id == 0) {
			if (cur_tsc > last_tsc + stats_timer) {
				gw_dump_port_stats(0);
				last_tsc = cur_tsc;
			}
		}
		nb_rx = rte_eth_rx_burst(0, params->queues[port_id], mbufs, VNF_RX_BURST_SIZE);
		for (j = 0; j < nb_rx; j++) {
			if (mbufs[j]->hash.rss == 0) {
				printf("core_id:%u,%s:0x%x,idx:%u", core_id, 
					mbufs[j]->ol_flags & PKT_RX_RSS_HASH ? "rss" : "norss", 
					mbufs[j]->hash.rss, total_pkts++);
			}
			if(core_id == 0 && no_offload == 0)
				gw_process_offload(mbufs[j]);
			rte_pktmbuf_free(mbufs[j]);
		}
		delt_tsc = rte_rdtsc() - cur_tsc;
		if (nb_rx)
			rte_atomic64_add(&gw_cpu[core_id].total_rx_time, delt_tsc);
	}
	printf("core %u exit\n",core_id);
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

static void
gw_info_usage(const char *prgname)
{
	printf("%s [EAL options] -- \n"
		"  --log_level: set log level\n"
		"  --stats_timer: set interval to dump stats information\n"
		"  --nb_queue: set queues number\n"
		"  --nb_desc: set describe number\n"
		"  --no_offload: test no hw offload\n",
		prgname);
}

static int
gw_parse_uint32(const char *uint32_value)
{
	char *end = NULL;
	uint32_t value;

	value = strtoul(uint32_value, &end, 10);
	if ((uint32_value[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	return value;
}

static int
gw_info_parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	char *prgname = argv[0];
	uint32_t log_level = 0;
	static struct option long_option[] = {
		{"log_level", 1, NULL, 0},
		{"stats_timer", 1, NULL, 1},
		{"nb_queue", 1, NULL, 2},
		{"nb_desc", 1, NULL, 3},
		{"no_offload", 1, NULL, 4},	
		{"meter_action", 1, NULL, 5},
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
			stats_timer = gw_parse_uint32(optarg);
			printf("set stats_timer:%lu\n", stats_timer);
			break;
		case 2:
			nr_queues = gw_parse_uint32(optarg);
			printf("set nr_queues:%u.\n", nr_queues);
			break;
		case 3:
			nb_desc = gw_parse_uint32(optarg);
			printf("set nb_desc:%u.\n", nb_desc);
			break;
		case 4:
			no_offload = gw_parse_uint32(optarg);
			printf("set no_offload:%u.\n", no_offload);
			break;			
		case 5:
			meter_action = gw_parse_uint32(optarg);
			printf("set meter_action:%u.\n", meter_action);
			break;				
		default:
			gw_info_usage(prgname);
			return -1;
		}
	}
	return 0;
}

static int
init_dpdk(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;
        int i;
        int total_cores = 0;

        memset(core_params_arr, 0, sizeof(core_params_arr));
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		DOCA_LOG_CRIT("invalid EAL arguments\n");
                return ret;
        }
	argc -= ret;
	argv += ret;

	gw_info_parse_args(argc, argv);
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

int
main(int argc, char **argv)
{
	int total_cores;
	int i = 0;

	if (init_dpdk(argc , argv)) {
		rte_exit(EXIT_FAILURE, "Cannot init dpdk\n");
		return -1;
	}

	stats_timer *= rte_get_timer_hz();
	total_cores = nr_queues;//count_lcores();
	DOCA_LOG_INFO("init ports: lcores = %d\n",total_cores);

	gw_init_port(0, total_cores);
	gw_init_port(1, total_cores);

	vnf = gw_get_doca_vnf();
	vnf->doca_vnf_init((void *)&total_cores);
	DOCA_LOG_INFO("VNF initiated!\n");
#if 0
	if (capture_en) {
		ph = doca_pcap_file_start(pcap_file_name);
	}
#endif
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
