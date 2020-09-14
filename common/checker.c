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

#include <arpa/inet.h>

int check_changes(int map_fd, int xdp_data_map_s_fd, int xdp_block_ip_fd)
{

  while(1){

    char * data = get_python_data();
    char * ipdata = NULL;


    if(!data || *data == 'z'){
      sleep(5);
    } else {

      switch(*data) {
        case 'b':
          ipdata = get_guardian_data();
          ipdata_to_bpfmap(ipdata, xdp_block_ip_fd);

          reset_python_data();
          break;
        case 's':
            kill(getppid(), 9);
            free_memory();
            close(map_fd);
            close(xdp_block_ip_fd);
            close(xdp_block_ip_fd);
            exit(0);
            break;
        case '2':
          break;


      }


    }


  }
}



int ipdata_to_bpfmap(char * data, int xdp_block_ip_fd){
  char *token = strtok(data, "|");



  if(token[0] == '0'){
    /* IPV4 */

    token = strtok(NULL, "|");
    int ipv4 = getDecimalValueOfIPV4_String(token);


    token = strtok(NULL, "|");


    int prefix = atoi(token);

    token = strtok(NULL, "|");


    time_t time = atoll(token);

    struct keyipblockh keyblock = {};
    keyblock.isv6 = 0;
    keyblock.ip_addr = htonl(ipv4);
    //keyblock.prefix = prefix;

    bpf_map_update_elem(xdp_block_ip_fd, &keyblock, &time, BPF_ANY);


  } else {
    /* IPV6 */

  }



  return 0;
























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
