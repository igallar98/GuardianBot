#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "shared_memory.h"
#include "checker.h"
#include <bpf/bpf.h>
#include <time.h>
#include <arpa/inet.h>
#define PATH "../data/"
#include "trace.h"
int check_changes(int map_fd, int xdp_data_map_s_fd, int xdp_block_ip_fd, int xdp_block_portsfd, int xdp_block_protofd, int xdp_perf_e)
{


  loadData_onStart(0, "ipBlocked.data", xdp_block_ip_fd);
  loadData_onStart(1, "portBlocked.data", xdp_block_portsfd);
  loadData_onStart(2, "protocolBlocked.data", xdp_block_protofd);
  int time = 50000;
  int hijo = -1;

  while(1){

    char data = get_python_data();
    char * bdata = NULL;

    update_time(xdp_block_protofd);


    if(data == 'z'){
      /*Espera ocupada*/
      if(time <= 50000)
        time+=50;

      usleep(time);

    } else {

      switch(data) {
        case 'b': /* Block IP */
          bdata = get_guardian_data();
          ipdatablock_to_bpfmap(bdata, xdp_block_ip_fd);
          reset_python_data();
          time=0;
          break;

        case 'u': /* UnBlock IP */
          bdata = get_guardian_data();

          delete_block_bpfmap(bdata, xdp_block_ip_fd);

          reset_python_data();
          time=0;
          break;

        case 'p': /* Block Protocol */
          bdata = get_guardian_data();

          block_protocol_bpfmap(bdata, xdp_block_protofd);

          reset_python_data();
          time=0;
          break;

        case 'd': /* UnBlock Protocol */
          bdata = get_guardian_data();

          unblock_protocol_bpfmap(bdata, xdp_block_protofd);

          reset_python_data();
          time=0;
          break;


        case '0': /* Block Port */
          bdata = get_guardian_data();

          block_port_bpfmap(bdata, xdp_block_portsfd);

          reset_python_data();
          time=0;
          break;


        case '1': /* UnBlock Port */
          bdata = get_guardian_data();

          unblock_port_bpfmap(bdata, xdp_block_portsfd);

          reset_python_data();
          time=0;
          break;

        case 'e': /* Start Tracing */
          bdata = get_guardian_data();
          if(hijo == -1)
            hijo = fork();
          if(hijo == 0) {
            trace_guardianbot(xdp_perf_e);
            exit(0);
          } else {

          reset_python_data();
          time=0;
          }
          break;

        case '8': /* Stop Tracing */
          bdata = get_guardian_data();
          if(hijo > 0)
            kill(hijo, SIGKILL);
          hijo = -1;
          reset_python_data();
          time=0;
          remove("../data/guardian.pcap");
          break;


        case 's': /* Shutdown */
            kill(getppid(), 9);
            free_memory();
            close(map_fd);
            close(xdp_data_map_s_fd);
            close(xdp_block_ip_fd);
            close(xdp_block_portsfd);
            close(xdp_block_protofd);
            close(xdp_perf_e);
            if(hijo != -1)
              kill(hijo, SIGKILL);
            exit(0);
            break;
        case 'c':
          break;
        case 'q':
          break;

      }


    }


  }
}


int loadData_onStart(int type, char * datafile, int xdp_fd){
  FILE *fptr;
  char filep[100] = PATH;
  long size = 0;
  strcat(filep, datafile);
  char *token;


  fptr = fopen(filep,"a+");
  if (fptr == NULL)
        return 1;

  fseek(fptr, 0, SEEK_END);
  size = ftell(fptr);
  fseek(fptr, 0, SEEK_SET);

  if (size == 0)
        return 0;


  /* +1 for size 0 */
  char fcontent[size+1];

  fread(fcontent, 1, size, fptr);

  token = strtok(fcontent, "\n");

  while( token != NULL ) {
    switch(type) {
      case 0:
        ipdatablock_to_bpfmap(token, xdp_fd);
        break;
      case 1:
        block_port_bpfmap(token, xdp_fd);
        break;
      case 2:
        block_protocol_bpfmap(token, xdp_fd);
        break;

  }
    token = strtok(NULL, "\n");
  }

  fclose(fptr);


  return 0;


}


int update_time(int xdp_block_protofd){
  time_t now = time(0);

  int p = 'm';


  bpf_map_update_elem(xdp_block_protofd, &p, &now, BPF_ANY);

  return 0;

}




int block_port_bpfmap(char * data, int xdp_block_portsfd){
  char *port = strtok(data, "|");

  if(port == NULL)
    return -1;

  __u16 p = htons(atoi(port));


  time_t time = atoll(strtok(NULL, "|"));

  bpf_map_update_elem(xdp_block_portsfd, &p, &time, BPF_ANY);

  return 0;

}

int unblock_port_bpfmap(char * data, int xdp_block_protofd) {
  char *port = strtok(data, "|");

  if(port == NULL)
    return -1;

  __u16 p = htons(atoi(port));

  bpf_map_delete_elem(xdp_block_protofd, &p);

  return 0;

}


int unblock_protocol_bpfmap(char * data, int xdp_block_protofd) {
  char *proto = strtok(data, "|");

  if(proto == NULL)
    return -1;
  char p = parse_proto(proto);

  bpf_map_delete_elem(xdp_block_protofd, &p);

  return 0;

}



int block_protocol_bpfmap(char * data, int xdp_block_protofd){
  char *proto = strtok(data, "|");

  if(proto == NULL)
    return -1;

  char p = parse_proto(proto);


  time_t time = atoll(strtok(NULL, "|"));

  bpf_map_update_elem(xdp_block_protofd, &p, &time, BPF_ANY);

  return 0;

}

char parse_proto(char *proto){
  char  p = 'x';
  if (strcmp(proto, "IP") == 0)
    p = 'p';
  else if (strcmp(proto, "IPV6") == 0)
    p = '6';
  else if (strcmp(proto, "ICMP") == 0)
    p = 'i';
  else if (strcmp(proto, "TCP") == 0)
    p = 't';
  else if (strcmp(proto, "UDP") == 0)
    p = 'u';

  return p;
}

int ipdatablock_to_bpfmap(char * data, int xdp_block_ip_fd){
  char *token = strtok(data, "|");
  if(token == NULL)
    return -1;


  if(token[0] == '0'){
    /* IPV4 */

    token = strtok(NULL, "|");
    int ipv4 = getDecimalValueOfIPV4_String(token);


    token = strtok(NULL, "|");


    //int prefix = atoi(token);

    token = strtok(NULL, "\n");


    time_t time = atoll(token);

    struct keyipblockchk keyblock = {};
    keyblock.isv6 = 0;
    keyblock.ip_addr = htonl(ipv4);


    //keyblock.prefix = prefix;

    bpf_map_update_elem(xdp_block_ip_fd, &keyblock, &time, BPF_ANY);


  } else {
    /* IPV6 */
    struct in6_addr resultip;


    token = strtok(NULL, "|");


    if (inet_pton(AF_INET6, token, &resultip) != 1)
      return -1;

    token = strtok(NULL, "|");


    //int prefix = atoi(token);

    token = strtok(NULL, "\n");


    time_t time = atoll(token);

    struct keyipblockchk keyblock = {};
    keyblock.isv6 = 1;
    keyblock.ip6_addr = resultip;

    bpf_map_update_elem(xdp_block_ip_fd, &keyblock, &time, BPF_ANY);

  }



  return 0;


}


int delete_block_bpfmap(char * data, int xdp_block_ip_fd){
  char *token = strtok(data, "|");

  if(token == NULL)
    return -1;


  if(token[0] == '0'){
    /* IPV4 */


    token = strtok(NULL, "\n");
    int ipv4 = getDecimalValueOfIPV4_String(token);

    struct keyipblockchk keyblock = {};
    keyblock.isv6 = 0;
    keyblock.ip_addr = htonl(ipv4);


    bpf_map_delete_elem(xdp_block_ip_fd, &keyblock);



  } else {
    /* IPv6 */

    struct in6_addr resultip;


    token = strtok(NULL, "|");


    if (inet_pton(AF_INET6, token, &resultip) != 1)
      return -1;


    struct keyipblockchk keyblock = {};
    keyblock.isv6 = 0;
    keyblock.ip6_addr = resultip;


    bpf_map_delete_elem(xdp_block_ip_fd, &keyblock);

  }

  return 1;


}

int IsDigit(char ch)
{
   int is_digit = 0;
   if ( ch >= '0' && ch <= '9' )
   {
      is_digit = 1;
   }
   return is_digit;
}



uint32_t getDecimalValueOfIPV4_String(const char* ipAddress)
{
    uint8_t ipbytes[4]={};
    int i =0;
    int8_t j=3;
    while (ipAddress+i && i<strlen(ipAddress))
    {
       char digit = ipAddress[i];
       if (IsDigit(digit) == 0 && digit!='.'){
           return 0;
       }
        j=digit=='.'?j-1:j;
       ipbytes[j]= ipbytes[j]*10 + atoi(&digit);

        i++;
    }

    uint32_t a = ipbytes[0];
    uint32_t b =  ( uint32_t)ipbytes[1] << 8;
    uint32_t c =  ( uint32_t)ipbytes[2] << 16;
    uint32_t d =  ( uint32_t)ipbytes[3] << 24;
    return a+b+c+d;
}
