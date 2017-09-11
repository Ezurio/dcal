#ifndef __lease_h__
#define __lease_h__

#include <stdbool.h>
#include "dcal_api.h"
#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)

#define LEASE_SMALL_STR_SZ 20
#define LEASE_LARGE_STR_SZ 100
#define LEASE_DOMAIN_STR_SZ 200
#define LEASE_TIMER_STR_SZ 30

typedef struct _internal_lease_handle {
	#ifdef STATIC_MEM
	int valid;
	#endif
	char interface[LEASE_SMALL_STR_SZ];
	char address[LEASE_SMALL_STR_SZ];
	char subnet_mask[LEASE_SMALL_STR_SZ];
	char routers[LEASE_LARGE_STR_SZ];
	long lease_time;
	int message_type;
	char dns_servers[LEASE_LARGE_STR_SZ];
	char dhcp_server[LEASE_SMALL_STR_SZ];
	char domain_name[LEASE_DOMAIN_STR_SZ];
	char renew[LEASE_TIMER_STR_SZ];
	char rebind[LEASE_TIMER_STR_SZ];
	char expire[LEASE_TIMER_STR_SZ];

} internal_lease_struct, * internal_lease_handle;


#endif //__lease_h__
