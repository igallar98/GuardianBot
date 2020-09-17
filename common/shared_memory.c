#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "shared_memory.h"
#define GETEKYDIR ("/tmp")
#define PROJECTID  8888
#define PROJECTIDRV 2244
#define GUARDIANDATA 2248
#define MAXTAMDATA 5000
#include <unistd.h>

int send_to_python(char * data, int tam)
{

    key_t key = PROJECTID;
    int shmid;

    shmid = shmget(key, tam , IPC_CREAT | IPC_EXCL | 0664);
    if ( shmid == -1 ) {
        if ( errno == EEXIST ) {
            shmid = shmget(key ,0, 0);
        } else {
            return -1;
        }
    }

    char *addr;

    if ( (addr = shmat(shmid, 0, 0) ) == (void*)-1) {
        if (shmctl(shmid, IPC_RMID, NULL) == -1)
            return -1;
        return -1;
    }

    strcpy( addr, data );



    if ( shmdt(addr) < 0)
        return -1;
    sleep(3);
    if (shmctl(shmid, IPC_RMID, NULL) == -1)
        return -1;


    return 0;
}




char* get_python_data(){

  key_t key = PROJECTIDRV;
  int shmid;

  shmid = shmget(key, sizeof('z') , IPC_CREAT | IPC_EXCL | 0664);
  if ( shmid == -1 ) {
      if ( errno == EEXIST ) {
          shmid = shmget(key ,0, 0);
      } else {
          return NULL;
      }
  }

  char *addr = NULL;

  if ( (addr = shmat(shmid, 0, 0) ) == (void*)-1) {
    return addr;
  }


  return addr;

}


int reset_python_data(){

  key_t key = PROJECTIDRV;
  int shmid;
  char value = 'z';

  shmid = shmget(key, sizeof('z') , IPC_CREAT | IPC_EXCL | 0664);
  if ( shmid == -1 ) {
      if ( errno == EEXIST ) {
          shmid = shmget(key ,0, 0);
      } else {
          return -1;
      }
  }

  char *addr = NULL;

  if ( (addr = shmat(shmid, 0, 0) ) == (void*)-1) {
    return -1;
  }

  strcpy( addr, &value );


  if ( shmdt(addr) < 0)
    return -1;


  return 0;
}




int free_memory(){

  key_t key = PROJECTIDRV;
  int shmid;


  shmid = shmget(key ,0, 0);
  if ( shmid == -1 )
      return -1;


  if (shmctl(shmid, IPC_RMID, NULL) == -1)
      return -1;


  key = PROJECTID;
  shmid = 0;

  shmid = shmget(key ,0, 0);
  if ( shmid == -1 )
      return -1;

  if (shmctl(shmid, IPC_RMID, NULL) == -1)
      return -1;


  key = GUARDIANDATA;
  shmid = 0;

  shmid = shmget(key ,0, 0);
  if ( shmid == -1 )
      return -1;

  if (shmctl(shmid, IPC_RMID, NULL) == -1)
      return -1;


  return 1;


}



char* get_guardian_data(){

  key_t key = GUARDIANDATA;
  int shmid;

  shmid = shmget(key, MAXTAMDATA , IPC_CREAT | IPC_EXCL | 0664);
  if ( shmid == -1 ) {
      if ( errno == EEXIST ) {
          shmid = shmget(key ,0, 0);
      } else {
          return NULL;
      }
  }

  char *addr = NULL;

  if ( (addr = shmat(shmid, 0, 0) ) == (void*)-1) {
    return addr;
  }

  if (shmctl(shmid, IPC_RMID, NULL) == -1)
      return NULL;

  shmid = shmget(key, MAXTAMDATA , IPC_CREAT | IPC_EXCL | 0664);


  return addr;

}
