#ifndef __interface_h__
#define __interface_h__

#include <stdbool.h>
#include "dcal_api.h"
#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)

#define STR_SZ 80

#define INTERFACE_DISABLE 1
#define INTERFACE_ENABLE  2

typedef struct _internal_interface_handle {
	#ifdef STATIC_MEM
	int valid;
	#endif
	char interface_name[STR_SZ];
	bool ipv4;
	char method[STR_SZ];
	int auto_start;
	char address[STR_SZ];
	char netmask[STR_SZ];
	char netmask6[STR_SZ];
	char gateway[STR_SZ];
	char nameserver[STR_SZ];
	char broadcast[STR_SZ];
	int state;
	char bridge_one[STR_SZ];
	char bridge_two[STR_SZ];
	int ap_mode;
	int nat;
	bool ipv6;
	char method6[STR_SZ];
	char address6[STR_SZ];
	char gateway6[STR_SZ];
	char nameserver6[STR_SZ];
	int state6;
	int nat6;

} internal_interface_struct, * internal_interface_handle;


#endif //__profile_h__
