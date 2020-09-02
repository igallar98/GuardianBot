/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdio.h>


#include "maps_kern.h"
#include "../common/parsing_helpers.h"


static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	__u32 key = -1;

	int ip_type, eth_type;
	struct ethhdr *eth;
	struct hdr_cursor nh;
	struct iphdr *iph;

	/* Packet parsing */
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type != bpf_htons(ETH_P_IP)) {
			return XDP_PASS;
	}


	ip_type = parse_iphdr(&nh, data_end, &iph);

	if(ip_type == -1)
		return XDP_PASS;


	key = iph->saddr;


	/* Update packet length */
	__u64 bytes = data_end - data;

	struct datarec aux = {0, 0};
	struct record auxrec = {{0, 0}, {{0, 0},{0, 0}}};

	struct datarec * rec = bpf_map_lookup_elem(&xdp_data_map, &key);
	if(!rec) {
		bpf_map_update_elem(&xdp_data_map, &key, &aux, BPF_NOEXIST);
		bpf_map_update_elem(&xdp_data_map_s, &key, &auxrec, BPF_NOEXIST);
		return XDP_PASS;
	}
	aux.rx_packets = rec->rx_packets;
	aux.rx_bytes = rec->rx_bytes;


	aux.rx_packets++;
	aux.rx_bytes += bytes;

	bpf_map_update_elem(&xdp_data_map, &key, &aux, BPF_ANY);

	return XDP_PASS;
}

SEC("xdp_pass")
int  xdp_pass_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx);
}

char _license[] SEC("license") = "GPL";
