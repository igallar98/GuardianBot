/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef MAPS_KERN_H
#define MAPS_KERN_H
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#include "../common/parsing_helpers.h"
#define IP_HASH_ENTRIES_MAX	16382

/* DATA IP MAP PER CPU */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u16   source;
	__u16   dest;
	char proto;
};

struct keyip {
	char isv6;
	__be32 	ip_saddr;
	__be32 	ip_daddr;
	struct in6_addr ip6_saddr;
	struct in6_addr ip6_daddr;
};


struct bpf_map_def SEC("maps") xdp_data_map = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(struct keyip),
	.value_size  = sizeof(struct datarec),
	.max_entries = IP_HASH_ENTRIES_MAX,
};


/* SUM DATA IP MAP */

struct record {
	__u64 timestamp[2];
	struct datarec total[2];
};


struct bpf_map_def SEC("maps") xdp_data_map_s = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct keyip),
	.value_size  = sizeof(struct record),
	.max_entries = IP_HASH_ENTRIES_MAX,
};


#endif

#endif /* MAPS_KERN_H */
