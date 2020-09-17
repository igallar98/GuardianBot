/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdio.h>


#include "maps_kern.h"
/* #define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
}) */



static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	int ip_type, eth_type;
	struct ethhdr *eth;
	struct hdr_cursor nh;
	struct iphdr *iph;
	struct ipv6hdr *ipv6hdr;
	struct keyip key = {};
	/*struct icmphdr_common *icmphdr;*/
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	int tcp_type, udp_type;

	struct keyipblock keyblock = {};



	/* Packet parsing */
	nh.pos = data;

	struct datarec aux = {0, 0, 0, 0, 0};
	struct record auxrec = {{0, 0}, {{0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}}};
	aux.proto = 'n';



	eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type == bpf_htons(ETH_P_IP)) {
			ip_type = parse_iphdr(&nh, data_end, &iph);
			aux.proto = 'p';

			if(ip_type == -1)
				return XDP_PASS;

			key.ip_saddr = iph->saddr;
			key.ip_daddr = iph->daddr;
			key.isv6 = 0;
			keyblock.ip_addr = iph->saddr;
			keyblock.isv6 = 0;


	} else if (eth_type == bpf_htons(ETH_P_IPV6)){
			ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
			aux.proto = '6';

			if(ip_type == -1)
					return XDP_PASS;

				key.ip6_saddr = ipv6hdr->saddr;
				key.ip6_daddr = ipv6hdr->daddr;
				key.isv6 = 1;
				keyblock.ip6_addr = ipv6hdr->saddr;
				keyblock.isv6 = 1;

	} else {
		return XDP_PASS;
	}

	/*time now */
	char n = 'm';
	time_t * now = bpf_map_lookup_elem(&xdp_block_proto, &n);
	time_t zero = 0;
	if(now == NULL){
		now = &zero;
	}


	/* IP block */

	time_t * timest = bpf_map_lookup_elem(&xdp_block_ip, &keyblock);

	if(timest){
		if(*now >= *timest)
			bpf_map_delete_elem(&xdp_block_ip, &keyblock);
		else
			return XDP_DROP;
	}



	switch(ip_type) {

	 case IPPROTO_ICMPV6 || IPPROTO_ICMP:
			/*icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);*/
			aux.proto = 'i';
			aux.source = 1;

			break;

	 case IPPROTO_TCP:
		 tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
		 if(tcp_type != -1){
			 aux.source = tcphdr->source;
			 aux.dest = tcphdr->dest;
			 aux.proto = 't';
		 }


		 break;

		case IPPROTO_UDP:
			udp_type = parse_udphdr(&nh, data_end, &udphdr);
			if(udp_type != -1){
				aux.source = udphdr->source;
				aux.dest = udphdr->dest;
				aux.proto = 'u';
			}

			break;
	}
	/* PORT block */

	time_t *timeport = bpf_map_lookup_elem(&xdp_block_ports, &aux.source);

	if(timeport){
		if(*now >= *timeport)
			bpf_map_delete_elem(&xdp_block_ports, &aux.source);
		else
			return XDP_DROP;
	}


	/* PROTO block */

	time_t * timeproto = bpf_map_lookup_elem(&xdp_block_proto, &aux.proto);
	if(timeproto){
		if(*now >= *timeproto)
			bpf_map_delete_elem(&xdp_block_proto, &aux.proto);
		else
			return XDP_DROP;
	}


	/* Update packet length */
	__u64 bytes = data_end - data;





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
