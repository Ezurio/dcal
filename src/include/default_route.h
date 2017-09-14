#ifndef __default_route_h__
#define __default_route_h__

#include <stdbool.h>
#include "dcal_api.h"
#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)

#define LRD_ROUTE_STR_SZ 20
#define LRD_ROUTE_FILE "/proc/net/route"

typedef struct _internal_default_route_handle {
	#ifdef STATIC_MEM
	int valid;
	#endif
	char interface[LRD_ROUTE_STR_SZ]; //Interface to which packets for this route will be sent.
	char destination[LRD_ROUTE_STR_SZ]; //Specifies which datagrams will match this route.
	char gateway[LRD_ROUTE_STR_SZ]; //The IP address of the host that will act as a gateway.
	int flags; //An indicator of a number of route attributes.
	unsigned int metric; //metric value associated with the route.
	char subnet_mask[LRD_ROUTE_STR_SZ]; //Specifies which datagrams will match this route.
	unsigned int mtu; //Specifies the largest TCP segment (in bytes).
	unsigned int window; //Specifies the TCP window (in bytes).
	unsigned int irtt; //Initial Round Trip time (in milliseconds).

} internal_default_route_struct, * internal_default_route_handle;


#endif //__default_route_h__
