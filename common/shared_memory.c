#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "shared_memory.h"
#define GETEKYDIR ("/tmp")
#define PROJECTID  (72181)
#include <unistd.h>

int send_to_python(char * data, int tam)
{

    key_t key = 18234;
    if ( key < 0 ){
      printf("err\n");
      return -1;
    }
    printf("%s\n", data);

    int shmid;
    shmid = shmget(key, tam , IPC_CREAT | IPC_EXCL | 0664);
    if ( shmid == -1 ) {
        if ( errno == EEXIST ) {
            printf("shared memeory already exist\n");
            shmid = shmget(key ,0, 0);
            printf("reference shmid = %d\n", shmid);
        } else {
            perror("errno");
            return -1;
        }
    }

    char *addr;

    if ( (addr = shmat(shmid, 0, 0) ) == (void*)-1) {
        if (shmctl(shmid, IPC_RMID, NULL) == -1)
            return -1;
        else {
            printf("Attach shared memory failed\n");
            printf("remove shared memory identifier successful\n");
        }

        return -1;
    }

    strcpy( addr, data );
    sleep(5);

    //printf("Enter to exit");
    //getchar();

    if ( shmdt(addr) < 0)
        return -1;

    if (shmctl(shmid, IPC_RMID, NULL) == -1)
        return -1;
    else {
        printf("Finally\n");
        printf("remove shared memory identifier successful\n");
    }

    return 0;
}
