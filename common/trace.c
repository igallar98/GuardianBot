// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "perf-sys.h"
#include "trace.h"
#include "shared_memory.h"
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#define NANOSECS_PER_USEC 1000
static pcap_t* pd;
static pcap_dumper_t* pdumper;
static unsigned int pcap_pkts;

static const char *default_filename = "../data/guardian.pcap";



#define MAX_CNT 100000ll

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{

  struct {
      __u16 pkt_len;
      __u16 cookie;
  		__u8  pkt_data[SAMPLE_SIZE];
  	} *e = data;

	if (e->cookie != 0xdade) {

		return;
	}

	struct pcap_pkthdr h = {
			.caplen	= SAMPLE_SIZE,
			.len	= e->pkt_len,
		};
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);

		h.ts.tv_sec  = ts.tv_sec;
		h.ts.tv_usec = ts.tv_nsec / NANOSECS_PER_USEC;
		pcap_dump((u_char *) pdumper, &h, e->pkt_data);
		pcap_pkts++;
}

int trace_guardianbot(int map_fd)
{
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	int ret;

  time_t endtime = time(0) + 10;


	pb_opts.sample_cb = print_bpf_output;
	pb = perf_buffer__new(map_fd, 8, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}


	while(1){
		pd = pcap_open_dead(DLT_EN10MB, 65535);
		if (!pd)
			break;
		pdumper = pcap_dump_open(pd, default_filename);
		if (!pdumper)
			break;
		pb = perf_buffer__new(map_fd, 8, &pb_opts);
		while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && time(0) < endtime) {

		}
		sleep(1);
		endtime = time(0) + 60;
		pcap_dump_close(pdumper);
		pcap_close(pd);
		remove(default_filename);

	}


	return ret;
}
