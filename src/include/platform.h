#ifndef __platform_h__
#define __platform_h__

#include <pthread.h>

#define MUTEX pthread_mutex_t

#define INIT_LOCK(x) do {((x) = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t))); pthread_mutex_init((x), NULL);} while(0)
#define DESTROY_LOCK(x) do {(pthread_mutex_destroy(x)); free(x);} while(0)
#define LOCK(x)  (pthread_mutex_lock(x))
#define UNLOCK(x) (pthread_mutex_unlock(x))

#endif // __platform_h__
