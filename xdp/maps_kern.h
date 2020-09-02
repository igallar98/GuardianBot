/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef MAPS_KERN_H
#define MAPS_KERN_H
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

/* DATA IP MAP PER CPU */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct bpf_map_def SEC("maps") xdp_data_map = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(__u32), /* IP */
	.value_size  = sizeof(struct datarec),
	.max_entries = 128,
};


/* SUM DATA IP MAP */

struct record {
	__u64 timestamp[2];
	struct datarec total[2];
};


struct bpf_map_def SEC("maps") xdp_data_map_s = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct record),
	.max_entries = 128,
};


#endif

#endif /* MAPS_KERN_H */
