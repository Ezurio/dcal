#ifndef __global_h__
#define __global_h__

#include <stdbool.h>
#include "dcal_api.h"
#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)

#define DEFAULT_PSP_DELAY 200  // msec

#define MAX_CERT_PATH 65

typedef struct _internal_global_handle {
	#ifdef STATIC_MEM
	bool valid;
	#endif
	unsigned int auth;
	unsigned int channel_set_a;
	unsigned int channel_set_b;
	bool auto_profile;
	unsigned int beacon_miss;
	bool bt_coex;
	bool ccx;
	char cert_path[MAX_CERT_PATH];
	bool date_check;
	unsigned int def_adhoc_channel;
	bool fips;
	unsigned int pmk;
	unsigned int probe_delay;
	unsigned int regdomain;
	unsigned int roam_period;
	unsigned int roam_trigger;
	unsigned int rts;
	unsigned int scan_dfs;
	unsigned int ttls_inner_method;
	bool uapsd;
	bool wmm;
	bool ignore_null_ssid;
	unsigned int dfs_channels;

} internal_global_struct, * internal_global_handle;


#endif //__global_h__
