/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef MAPS_USER_EXPECTED_H
#define MAPS_USER_EXPECTED_H

/* DATA IP PER CPU MAP EXCEPT */

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

const struct bpf_map_info map_expect = {
  .key_size    = sizeof(__u32),
  .value_size  = sizeof(struct datarec),
  .max_entries = 128,
};

/* SUM DATA IP MAP EXCEPT */
struct record {
	__u64 timestamp[2];
	struct datarec total[2];
};


const struct bpf_map_info xdp_data_map_s_ex = {
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct record),
	.max_entries = 128,
};



#endif /* MAPS_USER_EXPECTED_H */
