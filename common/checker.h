
#ifndef __CHECKER_H
#define __CHECKER_H
#include <linux/ip.h>
#include <linux/ipv6.h>
struct keyipblockchk {
	char isv6;
	__be32 	ip_addr;
	struct in6_addr ip6_addr;
};

int check_changes(int map_fd, int xdp_data_map_s_fd, int xdp_block_ip_fd, int xdp_block_portsfd, int xdp_block_protofd);
int ipdatablock_to_bpfmap(char * data, int xdp_block_ip_fd);
int delete_block_bpfmap(char * data, int xdp_block_ip_fd);

uint32_t getDecimalValueOfIPV4_String(const char* ipAddress);

int block_protocol_bpfmap(char * data, int xdp_block_protofd);
int unblock_protocol_bpfmap(char * data, int xdp_block_protofd) ;

char parse_proto(char *proto);

int IsDigit(char ch);
#endif /* __SHARED_MEMORY_H */
