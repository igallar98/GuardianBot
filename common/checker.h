
#ifndef __CHECKER_H
#define __CHECKER_H
#include <linux/ip.h>
#include <linux/ipv6.h>
struct keyipblockchk {
	char isv6;
	__be32 	ip_addr;
	struct in6_addr ip6_addr;
};

struct keyipchk {
	char isv6;
	__be32 	ip_saddr;
	__be32 	ip_daddr;
	struct in6_addr ip6_saddr;
	struct in6_addr ip6_daddr;
};


int check_changes(int map_fd, int xdp_data_map_s_fd, int xdp_block_ip_fd, int xdp_block_portsfd, int xdp_block_protofd, int xdp_perf_e);
int update_time(int xdp_block_protofd);
int loadData_onStart(int type, char * datafile, int xdp_fd);

int ipdatablock_to_bpfmap(char * data, int xdp_block_ip_fd);
int delete_block_bpfmap(char * data, int xdp_block_ip_fd);

uint32_t getDecimalValueOfIPV4_String(const char* ipAddress);

int block_protocol_bpfmap(char * data, int xdp_block_protofd);
int unblock_protocol_bpfmap(char * data, int xdp_block_protofd);

char parse_proto(char *proto);

int block_port_bpfmap(char * data, int xdp_block_portsfd);
int unblock_port_bpfmap(char * data, int xdp_block_protofd);

int IsDigit(char ch);
#endif /* __SHARED_MEMORY_H */
