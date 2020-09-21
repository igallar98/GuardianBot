
#ifndef __CONFIG_H
#define __CONFIG_H

#define FILE_CONFIG "../data/config.conf"

typedef struct _Config {
   int ppslimit;
   double mbitslimit;
   int timecheck;
   int blocktime;
   int deleteRegister;
} Config;


Config * init_config();

Config * reload_config(Config* conf);

int check_config(Config* conf);

void * destroy_config();
#endif /* __CONFIG_H */
