#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

//xdp_pass_kern.o: formato de archivo ELF64-BPF
//Desmontaje de la sección xdp:

SEC("xdp")
int  xdp_pass(struct xdp_md *ctx) //xdp_prog_simple:
{ //0: b7 00 00 00 02 00 00 00 	r0 = 2
	return XDP_PASS;//1: 95 00 00 00 00 00 00 00 exit
}