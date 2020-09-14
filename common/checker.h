
#ifndef __CHECKER_H
#define __CHECKER_H
#include <linux/ip.h>
#include <linux/ipv6.h>
struct keyipblockh {
	char isv6;
	__be32 	ip_addr;
	struct in6_addr ip6_addr;
};

int check_changes(int map_fd, int xdp_data_map_s_fd, int xdp_block_ip_fd);
int ipdata_to_bpfmap(char * data, int xdp_block_ip_fd);
uint32_t getDecimalValueOfIPV4_String(const char* ipAddress);
int IsDigit(char ch);
#endif /* __SHARED_MEMORY_H */
