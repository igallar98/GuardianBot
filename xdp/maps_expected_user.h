/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
 #include <linux/ip.h>
 #include <linux/ipv6.h>
#ifndef MAPS_USER_EXPECTED_H
#define MAPS_USER_EXPECTED_H
#define IP_HASH_ENTRIES_MAX	32767


/* DATA IP PER CPU MAP EXCEPT */

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};
struct keyip {
		int isv6;
	__be32 	ip_saddr;
	__be32 	ip_daddr;
	struct in6_addr ip6_saddr;
	struct in6_addr ip6_daddr;
};
const struct bpf_map_info map_expect = {
  .key_size    = sizeof(struct keyip),
  .value_size  = sizeof(struct datarec),
  .max_entries = IP_HASH_ENTRIES_MAX,
};

/* SUM DATA IP MAP EXCEPT */
struct record {
	__u64 timestamp[2];
	struct datarec total[2];
};


const struct bpf_map_info xdp_data_map_s_ex = {
	.key_size    = sizeof(struct keyip),
	.value_size  = sizeof(struct record),
	.max_entries = IP_HASH_ENTRIES_MAX,
};



#endif /* MAPS_USER_EXPECTED_H */
