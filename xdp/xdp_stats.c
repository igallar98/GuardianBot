/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP data program\n"
	" - Finding xdp_data_map via --dev name info\n";

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>


#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */

#include "maps_expected_user.h"
#include "../common/shared_memory.h"


static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *rec)
{
	double period_ = 0;
	__u64 period = 0;

	period = rec->timestamp[1] - rec->timestamp[0];
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

char * string_ip6(struct in6_addr * addr){
			char * ipbytes;
			asprintf(&ipbytes, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
     	(int)addr->s6_addr[0], (int)addr->s6_addr[1],
			(int)addr->s6_addr[2], (int)addr->s6_addr[3],
			(int)addr->s6_addr[4], (int)addr->s6_addr[5],
			(int)addr->s6_addr[6], (int)addr->s6_addr[7],
			(int)addr->s6_addr[8], (int)addr->s6_addr[9],
			(int)addr->s6_addr[10], (int)addr->s6_addr[11],
			(int)addr->s6_addr[12], (int)addr->s6_addr[13],
			(int)addr->s6_addr[14], (int)addr->s6_addr[15]);
			return ipbytes;
}

char * string_ip(__be32 ip){

			unsigned char ipbytes[4];
	    ipbytes[0] = ip & 0xFF;
	    ipbytes[1] = (ip >> 8) & 0xFF;
	    ipbytes[2] = (ip >> 16) & 0xFF;
	    ipbytes[3] = (ip >> 24) & 0xFF;
			char *rbytes = "";

			asprintf(&rbytes, "%d.%d.%d.%d",ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]);

			return rbytes;
}



char * stats_print( int fd, int xdp_data_map_s_fd, int * tam)
{
	struct record aux = {{0, 0}, {{0, 0},{0, 0}}};
	struct record *rec = &aux;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	struct keyip key = {};
	char * data = "";
	char * ips;
	char * ipd;

	while (bpf_map_get_next_key(xdp_data_map_s_fd, &key, &key) == 0)
	{

		bpf_map_lookup_elem(xdp_data_map_s_fd, &key, rec);


		/*isipv6 | saddr | daddr | pkts | pps | kb | Mbits/s | periodo*/

		char *fmt = "%s%d|%s|%s|%lld|%.0f|"
			"%lld|%0.f|"
			"%f\n";

		if(key.isv6 == 1){
			ips = string_ip6(&key.ip6_saddr);
			ipd = string_ip6(&key.ip6_daddr);

		} else {

			ips = string_ip(key.ip_saddr);
			ipd = string_ip(key.ip_daddr);

		}




		period = calc_period(rec);
		if (period == 0)
		       return "";

		packets = rec->total[1].rx_packets - rec->total[0].rx_packets;
		pps     = packets / period;

		bytes   = rec->total[1].rx_bytes   - rec->total[0].rx_bytes;
		bps     = (bytes * 8)/ period / 1000000;

		/* Reservar memoria e imprimir en string*/


		*tam =  asprintf(&data, fmt, data, key.isv6, ips, ipd , rec->total[1].rx_packets, pps,
		       rec->total[1].rx_bytes / 1000 , bps,
		       period);

		/*printf("%s\n", data);*/

		free(ips);
		free(ipd);
	}


	return data;
}


void map_get_value_percpu_array(int fd, struct keyip key, struct datarec *value)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i = 0;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0)
		return;


	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;


}

static bool map_collect(int fd, struct keyip key, struct record *rec, int xdp_data_map_s_fd, int idrec)
{
	struct datarec value;

	rec->timestamp[idrec] = gettime();

	map_get_value_percpu_array(fd, key, &value);

	rec->total[idrec].rx_packets = value.rx_packets;
	rec->total[idrec].rx_bytes   = value.rx_bytes;
	bpf_map_update_elem(xdp_data_map_s_fd, &key, rec, BPF_ANY);

	return true;
}

static void stats_collect(int map_fd, int xdp_data_map_s_fd, int idrec)
{
	struct keyip key = {};


	while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {

		struct record rec = {{0, 0}, {{0, 0},{0, 0}}};
		bpf_map_lookup_elem(xdp_data_map_s_fd, &key, &rec);
		map_collect(map_fd, key, &rec, xdp_data_map_s_fd, idrec);

	}
}

static int stats_poll(const char *pin_dir, int map_fd, __u32 id, int interval, int xdp_data_map_s_fd)
{
	struct bpf_map_info info = {};

	setlocale(LC_NUMERIC, "en_US");



	while (1) {


		map_fd = open_bpf_map_file(pin_dir, "xdp_data_map", &info);
		if (map_fd < 0) {
			return EXIT_FAIL_BPF;
		}
		/* else if (id != info.id) {
			printf("BPF map xdp_data_map changed its ID, restarting\n");
			close(map_fd);
			return 0;
		} */

		xdp_data_map_s_fd = open_bpf_map_file(pin_dir, "xdp_data_map_s", &info);
		if (xdp_data_map_s_fd < 0) {
			return EXIT_FAIL_BPF;
		}
		/* else if (id != info.id) {
			printf("BPF map xdp_data_map changed its ID, restarting\n");
			close(map_fd);
			return 0;
		} */


		stats_collect(map_fd, xdp_data_map_s_fd, 0);
		usleep(2000000);
		stats_collect(map_fd, xdp_data_map_s_fd, 1);
		int tam = 0;
		char * data = stats_print(map_fd, xdp_data_map_s_fd, &tam);

		send_to_python(data, tam);

		free(data);

		close(map_fd);
		close(xdp_data_map_s_fd);
		sleep(interval);
	}

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{

	struct bpf_map_info info = { 0 };
	char pin_dir[PATH_MAX];
	int stats_map_fd;
	int xdp_data_map_s_fd;
	int interval = 2;
	int len, err;

	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	for ( ;; ) {
		stats_map_fd = open_bpf_map_file(pin_dir, "xdp_data_map", &info);
		if (stats_map_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		/* check map info, e.g. datarec is expected size */
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			close(stats_map_fd);
			return err;
		}

		xdp_data_map_s_fd = open_bpf_map_file(pin_dir, "xdp_data_map_s", &info);
		if (xdp_data_map_s_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		/* check map info, e.g. datarec is expected size */
		err = check_map_fd_info(&info, &xdp_data_map_s_ex);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			close(stats_map_fd);
			return err;
		}
		if (verbose) {
			printf("\nCollecting stats from BPF map\n");
			printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			       " key_size:%d value_size:%d max_entries:%d\n",
			       info.type, info.id, info.name,
			       info.key_size, info.value_size, info.max_entries
			       );
		}

		err = stats_poll(pin_dir, stats_map_fd, info.id, interval, xdp_data_map_s_fd);
		close(stats_map_fd);
		if (err < 0)
			return err;
	}

	return EXIT_OK;
}
