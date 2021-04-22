#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "doca_pcap.h"

static const uint32_t DP_MAGIC_NUM_FLIP = 0xd4c3b2a1;
static const uint32_t DP_MAGIC_NUM_DONT_FLIP = 0xa1b2c3d4;
static int DP_FLIP;

struct doca_pcap_hander {
	FILE *fd;
};

struct pcap_file_header {
	uint32_t magicNum;
	uint16_t vmajor;
	uint16_t vminor;
	uint32_t timezome;
	uint32_t sigfig;
	uint32_t snaplen;
	uint32_t linktype;
};

struct pcap_pkt_header {
	uint32_t val_sec;
	uint32_t val_msec;
	uint32_t cap_len;
	uint32_t pkt_len;
};

struct doca_pcap_hander *doca_pcap_file_start(const char *filename)
{
	size_t n;
	struct doca_pcap_hander *p_handler;
	struct pcap_file_header hdr;
	FILE *fd = fopen(filename, "wb");

	if (!fd)
		return NULL;

	hdr.magicNum = DP_FLIP ? DP_MAGIC_NUM_FLIP : DP_MAGIC_NUM_DONT_FLIP;
	hdr.vmajor = 2;
	hdr.vminor = 4;
	hdr.timezome = 0;
	hdr.sigfig = 0;
	hdr.snaplen = 0xffff;
	hdr.linktype = 1;

	n = fwrite(&hdr, 1, sizeof(struct pcap_file_header), fd);
	p_handler =
	    (struct doca_pcap_hander *)malloc(sizeof(struct doca_pcap_hander));

	if (n != sizeof(struct pcap_file_header) || p_handler == NULL) {
		fclose(fd);
		return NULL;
	}
	memset(p_handler, 0, sizeof(struct doca_pcap_hander));
	p_handler->fd = fd;
	return p_handler;
}

int doca_pcap_write(struct doca_pcap_hander *p_handler, uint8_t *buff,
		    int buff_len, uint64_t timestamp, int cap_len)
{
	size_t n;
	struct pcap_pkt_header pkt_hdr;

	if (!p_handler)
		return -1;
	pkt_hdr.val_sec = timestamp / 1000000;
	pkt_hdr.val_msec = timestamp % 1000000;
	pkt_hdr.cap_len = cap_len > 0 ? cap_len : buff_len;
	pkt_hdr.pkt_len = buff_len;
	n = fwrite(&pkt_hdr, 1, sizeof(struct pcap_pkt_header), p_handler->fd);
	if (n < sizeof(struct pcap_pkt_header))
		return n;
	n = fwrite(buff, 1, pkt_hdr.cap_len, p_handler->fd);
	return n;
}

void doca_pcap_file_stop(struct doca_pcap_hander *p_handler)
{
	fclose(p_handler->fd);
	free(p_handler);
}
