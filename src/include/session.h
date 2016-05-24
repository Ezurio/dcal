#ifndef __session_h__
#define __session_h__

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdbool.h>
#include "flatcc/dcal_builder.h"
#include "dcal_api.h"

#define HOST_SZ 256
#define USER_SZ 64

typedef struct _internal_session_handle {
	#ifdef STATIC_MEM
	bool valid;
	#endif
	uint32_t version;
	uint8_t state;
	ssh_session ssh;
	char host[HOST_SZ];
	char user[USER_SZ];
	char pw[USER_SZ];
	unsigned int port;
	ssh_channel channel;
	int verbosity;
	flatcc_builder_t builder;
	bool builder_init;
} internal_session_struct;
typedef internal_session_struct * internal_session_handle;

// session states
#define SESSION_INVALID 0
#define SESSION_ALLOCATED 1
#define SESSION_ERROR 2
#define SESSION_ACTIVE 3

#define DEF_PORT 2222
#define KEYS_FOLDER "./test/"
#define SSHD_USER "libssh"
#define SSHD_PASSWORD "libssh"
#define LAIRD_HELLO "HELLO DCAS"

// internal use only
int dcal_send_buffer(laird_session_handle s, void * buffer, size_t nbytes);
// internal use only
int dcal_read_buffer(laird_session_handle s, void * buffer, size_t *nbytes);

#endif //__session_h__
