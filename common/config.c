#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#define TAM_BUFFER 20



Config * init_config() {
  Config * conf = NULL;
  char line[TAM_BUFFER];
  FILE * fp;
  conf = (Config*) malloc(sizeof(Config));

  if(!conf)
    return NULL;

  conf->ppslimit = 0;
  conf->mbitslimit = 0;
  conf->timecheck = 0;
  conf->blocktime = 0;
  conf->deleteRegister = 0;

  fp = fopen(FILE_CONFIG, "r");
  fgets(line, sizeof(line), fp);
  if(!fp){
    return conf;
  }


  conf->ppslimit =  atoi(strtok(line, "|"));
  conf->mbitslimit = atoi(strtok(NULL, "|"));
  conf->timecheck = atoi(strtok(NULL, "|"));
  conf->blocktime = atoi(strtok(NULL, "|"));
  conf->deleteRegister = atoi(strtok(NULL, "\n"));

  fclose(fp);

  return conf;

}

Config * reload_config(Config* conf){
  destroy_config(conf);
  return init_config();

}


int check_config(Config* conf){
  return (((conf->ppslimit > 0) && (conf->timecheck > 0) && (conf->blocktime > 0))
  || ((conf->mbitslimit > 0)  && (conf->timecheck > 0) && (conf->blocktime > 0))
  || ((conf->mbitslimit > 0)  && ((conf->mbitslimit > 0) && (conf->timecheck > 0) && (conf->blocktime > 0))));
}

void * destroy_config(Config * conf) {
  if(conf)
    free(conf);
  return NULL;
}
