#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "shared_memory.h"
#define GETEKYDIR ("/tmp")
#define PROJECTID  8888
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
    sleep(5);
    if (shmctl(shmid, IPC_RMID, NULL) == -1)
        return -1;


    return 0;
}
