#ifndef __SHARED_MEMORY_H
#define __SHARED_MEMORY_H




int send_to_python(char * data, int tam);
char get_python_data();
int send_trace(char * data, int tam);
int reset_trace();
int create_checker_smemory();
int reset_python_data();
int free_memory();
char * get_guardian_data();



#endif /* __SHARED_MEMORY_H */
