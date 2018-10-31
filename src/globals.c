#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_api.h"
#include "dcal_internal_api.h"
#include "globals.h"
#include "session.h"
#include "buffer.h"
#include "common.h"

#ifdef STATIC_MEM

static internal_global_struct static_globals = { 0 };

#else

#include "lists.h"
static pointer_list * globals = NULL;

#endif

void __attribute__ ((constructor)) initglobals(void)
{
	int rc;
	rc = initlist(&globals);
	if (rc)
		DBGERROR("initlist() failed for globals list with:%d\n", rc);
}

void __attribute__ ((destructor)) globals_fini(void)
{
	int rc;
	rc = freelist(&globals);
	globals = NULL;
	if(rc)
		DBGERROR("freelist() failed for globals list with: %d\n", rc);
}

int dcal_wifi_global_create( laird_global_handle * global)
{
	internal_global_handle handle=NULL;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (global==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else {
	#if STATIC_MEM
		if(static_global.valid)
			ret = DCAL_HANDLE_IN_USE;
		else
			handle = &static_global;
			memset(handle, 0, sizeof(internal_global_struct));
	#else // not STATIC_MEM
	#ifdef DEBUG
		if(validate_handle(globals, global))
			ret = DCAL_HANDLE_IN_USE;
		else
	#endif
		{
			handle = (internal_global_handle) malloc(sizeof(internal_global_struct));
			if (handle==NULL)
				ret = DCAL_NO_MEMORY;
			else {
				memset(handle, 0, sizeof(internal_global_struct));
				ret = add_to_list(&globals, handle);
				// global defaults
			}
		}
	#endif // STATIC_MEM
	}
	if (ret==DCAL_SUCCESS)
		*global = handle;
	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_pull( laird_session_handle session,
                                 laird_global_handle * global)
{
	int ret = DCAL_SUCCESS;
	REPORT_ENTRY_DEBUG;


	if ((session==NULL) || (global==NULL))
		ret = DCAL_INVALID_PARAMETER;
	#ifdef DEBUG
	else if (validate_handle(globals, global))
		ret = DCAL_HANDLE_IN_USE;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	#endif
	else {
		internal_session_handle s = (internal_session_handle)session;
		// Attempt to retrieve global from device
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_command_add(B, ns(Commands_GETGLOBALS)));
		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);
		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS)
		{
			unlock_session_channel(session);
			return REPORT_RETURN_DBG(ret);
		}
		//get response
		size=BUF_SZ;
		ret = dcal_read_buffer(session, buffer, &size);
		unlock_session_channel(session);

		if (ret != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		//is return buffer an ack buffer?
		buftype = verify_buffer(buffer, size);

		if(buftype != ns(Globals_type_hash)) {
			if(buftype != ns(Handshake_type_hash)){
				DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
				return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
			}

			ret =handshake_error_code(ns(Handshake_as_root(buffer)));

			DBGERROR("Failed to retrieve globals.  Error received: %d\n",ret);
			return REPORT_RETURN_DBG(ret);
		}

		//if valid, get handle (ifdef for STATIC or not)
		dcal_wifi_global_create( global);

		assert(*global);
		//copy data from buffer to handle
		internal_global_handle g = (internal_global_handle)*global;

		ns(Globals_table_t) gt = ns(Globals_as_root(buffer));

		g->auth=ns(Globals_auth(gt));
		g->channel_set_a=ns(Globals_channel_set_a(gt));
		g->channel_set_b=ns(Globals_channel_set_b(gt));
		g->auto_profile=ns(Globals_auto_profile(gt));
		g->beacon_miss=ns(Globals_beacon_miss(gt));
		g->ccx=ns(Globals_ccx(gt));
		strncpy(g->cert_path, ns(Globals_cert_path(gt)), MAX_CERT_PATH);
		g->date_check=ns(Globals_date_check(gt));
		g->def_adhoc_channel=ns(Globals_def_adhoc(gt));
		g->fips=ns(Globals_fips(gt));
		g->pmk=ns(Globals_pmk(gt));
		g->probe_delay=ns(Globals_probe_delay(gt));
		g->regdomain=ns(Globals_regdomain(gt));
		g->roam_periodms=ns(Globals_roam_periodms(gt));
		g->roam_trigger=ns(Globals_roam_trigger(gt));
		g->rts=ns(Globals_rts(gt));
		g->scan_dfs=ns(Globals_scan_dfs(gt));
		g->ttls_inner_method=ns(Globals_ttls(gt));
		g->uapsd=ns(Globals_uapsd(gt));
		g->wmm=ns(Globals_wmm(gt));
		g->ignore_null_ssid=ns(Globals_ignore_null_ssid(gt));
		g->dfs_channels=ns(Globals_dfs_channels(gt));

		#ifdef STATIC_MEM
		g->valid = true;
		#endif

	}
	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_close_handle( laird_global_handle g)
{
	internal_global_handle global = (internal_global_handle)g;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, g))
		ret = DCAL_INVALID_HANDLE;
	else {
		#ifdef STATIC_MEM
			((internal_global_handle)global)->valid = false;
		#else
			ret = remove_from_list(&globals, global);
			if (ret==DCAL_SUCCESS)
				global = NULL;
		#endif
	}

	return REPORT_RETURN_DBG(ret);

}

int dcal_wifi_global_push( laird_session_handle session,
                                 laird_global_handle global)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	internal_session_handle s = (internal_session_handle)session;
	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	else {
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));

		ns(Command_start(B));
		ns(Command_command_add(B, ns(Commands_SETGLOBALS)));

		ns(Command_cmd_pl_Globals_start(B));

		ns(Globals_auth_add(B, g->auth));
		ns(Globals_channel_set_a_add(B, g->channel_set_a));
		ns(Globals_channel_set_b_add(B, g->channel_set_b));
		ns(Globals_auto_profile_add(B, g->auto_profile));
		ns(Globals_beacon_miss_add(B, g->beacon_miss));
		ns(Globals_ccx_add(B, g->ccx));
		ns(Globals_cert_path_create_str(B, g->cert_path));
		ns(Globals_date_check_add(B, g->date_check));
		ns(Globals_def_adhoc_add(B, g->def_adhoc_channel));
		ns(Globals_fips_add(B, g->fips));
		ns(Globals_pmk_add(B, g->pmk));
		ns(Globals_probe_delay_add(B, g->probe_delay));
		ns(Globals_regdomain_add(B, g->regdomain));
		ns(Globals_roam_periodms_add(B, g->roam_periodms));
		ns(Globals_roam_trigger_add(B, g->roam_trigger));
		ns(Globals_rts_add(B, g->rts));
		ns(Globals_scan_dfs_add(B, g->scan_dfs));
		ns(Globals_ttls_add(B, g->ttls_inner_method));
		ns(Globals_uapsd_add(B, g->uapsd));
		ns(Globals_wmm_add(B, g->wmm));
		ns(Globals_ignore_null_ssid_add(B, g->ignore_null_ssid));
		ns(Globals_dfs_channels_add(B, g->dfs_channels));
		ns(Command_cmd_pl_Globals_end(B));

		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);
		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS){
			unlock_session_channel(session);
			return REPORT_RETURN_DBG(ret);
		}

		//get response
		size=BUF_SZ;
		ret = dcal_read_buffer(session, buffer, &size);
		unlock_session_channel(session);

		if (ret != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		//is return buffer an ack buffer?
			buftype = verify_buffer(buffer, size);

		if(buftype != ns(Handshake_type_hash)){
			DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
			return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
		}

		ret = handshake_error_code(ns(Handshake_as_root(buffer)));

	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_auth_server( laird_global_handle global,
                                      SERVER_AUTH auth)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if ((auth<TYPE1) || (auth>TYPE2))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->auth = auth;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_auth_server( laird_global_handle global,
                                      SERVER_AUTH *auth)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (auth==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*auth = g->auth;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_achannel_mask( laird_global_handle global,
                                        unsigned int channel_set_a)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->channel_set_a = channel_set_a;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_achannel_mask( laird_global_handle global,
                                        unsigned int *channel_set_a)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (channel_set_a==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*channel_set_a = g->channel_set_a;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_bchannel_mask( laird_global_handle global,
                                        unsigned int channel_set_b)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->channel_set_b = channel_set_b;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_bchannel_mask( laird_global_handle global,
                                        unsigned int *channel_set_b)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (channel_set_b==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*channel_set_b = g->channel_set_b;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_auto_profile( laird_global_handle global,
                                       bool auto_profile)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->auto_profile = auto_profile;
	}

	return REPORT_RETURN_DBG(ret);
}
int dcal_wifi_global_get_auto_profile( laird_global_handle global,
                                       bool *auto_profile)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (auto_profile==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*auto_profile = g->auto_profile;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_beacon_miss( laird_global_handle global,
                                      unsigned int beacon_miss)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->beacon_miss = beacon_miss;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_beacon_miss( laird_global_handle global,
                                      unsigned int *beacon_miss)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (beacon_miss==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*beacon_miss = g->beacon_miss;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_ccx( laird_global_handle global, bool ccx)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->ccx = ccx;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_ccx( laird_global_handle global, bool *ccx)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (ccx==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*ccx = g->ccx;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_cert_path( laird_global_handle global,
                                    char *cert_path)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(g->cert_path, cert_path, MAX_CERT_PATH);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_cert_path( laird_global_handle global,
                                    char *cert_path, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if ((cert_path==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(cert_path, g->cert_path, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_date_check( laird_global_handle global,
                                     bool date_check)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->date_check = date_check;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_date_check( laird_global_handle global,
                                     bool *date_check)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (date_check==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*date_check = g->date_check;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_def_adhoc_channel( laird_global_handle global,
                                            unsigned int def_adhoc_channel)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (def_adhoc_channel > b_14)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->def_adhoc_channel = def_adhoc_channel;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_def_adhoc_channel( laird_global_handle global,
                                            unsigned int *def_adhoc_channel)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (def_adhoc_channel==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*def_adhoc_channel = g->def_adhoc_channel;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_fips( laird_global_handle global, bool fips)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->fips = fips;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_fips( laird_global_handle global, bool *fips)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (fips==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*fips = g->fips;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_pmk( laird_global_handle global, DCAL_PMK_CACHING pmk)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if ((pmk < STANDARD) || (pmk > OPMK))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->pmk = pmk;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_pmk( laird_global_handle global, DCAL_PMK_CACHING *pmk)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (pmk==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*pmk = g->pmk;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_probe_delay( laird_global_handle global,
                                      unsigned int probe_delay)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->probe_delay = probe_delay;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_probe_delay( laird_global_handle global,
                                      unsigned int *probe_delay)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (probe_delay==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*probe_delay = g->probe_delay;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_regdomain( laird_global_handle global,
                                    REG_DOMAIN *regdomain)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (regdomain==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*regdomain = g->regdomain;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_roam_periodms( laird_global_handle global,
                                      unsigned int roam_periodms)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->roam_periodms = roam_periodms;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_roam_periodms( laird_global_handle global,
                                      unsigned int *roam_periodms)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (roam_periodms==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*roam_periodms = g->roam_periodms;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_roam_trigger( laird_global_handle global,
                                       unsigned int roam_trigger)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->roam_trigger = roam_trigger;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_roam_trigger( laird_global_handle global,
                                       unsigned int *roam_trigger)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (roam_trigger==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*roam_trigger = g->roam_trigger;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_rts( laird_global_handle global,
                              unsigned int rts)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->rts = rts;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_rts( laird_global_handle global,
                              unsigned int *rts)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (rts==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*rts = g->rts;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_scan_dfs_time( laird_global_handle global,
                                        unsigned int scan_dfs)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->scan_dfs = scan_dfs;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_scan_dfs_time( laird_global_handle global,
                                        unsigned int *scan_dfs)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (scan_dfs==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*scan_dfs = g->scan_dfs;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_ttls_inner_method( laird_global_handle global,
                                TTLS_INNER_METHOD ttls_inner_method)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if ((ttls_inner_method < TTLS_AUTO) || (ttls_inner_method>TTLS_EAP_MSCHAPV2))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->ttls_inner_method = ttls_inner_method;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_ttls_inner_method( laird_global_handle global,
                                TTLS_INNER_METHOD *ttls_inner_method)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (ttls_inner_method==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*ttls_inner_method = g->ttls_inner_method;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_uapsd( laird_global_handle global, bool uapsd)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (uapsd)
			g->uapsd = (AC_VO | AC_VI | AC_BK | AC_BE);
		else
			g->uapsd = 0;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_uapsd( laird_global_handle global, bool *uapsd)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (uapsd==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (g->uapsd == 0)
			*uapsd = g->uapsd;
		else
			*uapsd = 1;
	}

	return REPORT_RETURN_DBG(ret);
}


int dcal_wifi_global_set_uapsd_mask( laird_global_handle global, unsigned int uapsd)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->uapsd = uapsd;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_uapsd_mask( laird_global_handle global, unsigned int *uapsd)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (uapsd==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*uapsd = g->uapsd;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_wmm( laird_global_handle global, bool wmm)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->wmm = wmm;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_wmm( laird_global_handle global, bool *wmm)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (wmm==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*wmm = g->wmm;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_ignore_null_ssid( laird_global_handle global,
                                           bool ignore_null_ssid)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->ignore_null_ssid = ignore_null_ssid;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_ignore_null_ssid( laird_global_handle global,
                                           bool *ignore_null_ssid)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (ignore_null_ssid==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*ignore_null_ssid = g->ignore_null_ssid;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_set_dfs_channels( laird_global_handle global,
                                       DFS_CHANNELS dfs_channels)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		g->dfs_channels = dfs_channels;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_global_get_dfs_channels( laird_global_handle global,
                                       DFS_CHANNELS *dfs_channels)
{
	int ret = DCAL_SUCCESS;
	internal_global_handle g = (internal_global_handle)global;
	REPORT_ENTRY_DEBUG;

	if (dfs_channels==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(globals, global))
		ret = DCAL_INVALID_HANDLE;
	else {
		*dfs_channels = g->dfs_channels;
	}

	return REPORT_RETURN_DBG(ret);
}

// for use when debugging - may remove before publishing
#define BCHANS 14
#define ACHANS 24
void dcal_wifi_global_printf( laird_global_handle global)
{
	internal_global_handle g = (internal_global_handle)global;
	char * str=NULL;
	int i;
	bool comma = false;

	char *bchannels[BCHANS] = {
		"1", "2", "3", "4", "5", "6", "7",
		"8", "9", "10", "11", "12", "13", "14" };

	char *achannels[ACHANS] = {
		"36", "40", "44", "48", "52", "56", "60", "64", "100", "104",
	"108", "112", "116", "120", "124", "128", "132", "136", "140",
	"149", "153", "157", "161", "165" };

	printf("Globals:\n");

	if (g==NULL) {
		printf("is null\n");
		return;
	}
	else if(!validate_handle(globals, global)) {
		printf("invalid global handle\n");
		return;
	}
#ifdef STATIC_MEM
	printf("\tvalid: %svalid\n",g->valid?"":"not ");
#endif
	printf("A Channel Set: ");
	if (g->channel_set_a >= 0xffffff)
		printf("Full\n");
	else if (g->channel_set_a == 0)
		printf("None\n");
	else {
		comma = false;
		for (i=0; i<ACHANS; i++)
			if(g->channel_set_a & (1<<i)){
				printf("%s%s", (comma?", ":""),achannels[i]);
				comma = true;
			}
		printf("\n");
	}
	printf("Auth Server Type: ");
	switch(g->auth){
		case TYPE1: printf("Type 1\n"); break;
		case TYPE2: printf("Type 2\n"); break;
		default: printf("invalid\n");
	}
	printf("Auto Profile: %s\n", g->auto_profile?"On":"Off");
	printf("BG Channel Set: ");
	if (g->channel_set_b >= 0x3fff)
		printf("Full\n");
	else if (g->channel_set_b == 0)
		printf("None\n");
	else {
		comma=false;
		for (i=0; i<BCHANS; i++)
			if(g->channel_set_b & (1<<i)){
				printf("%s%s", (comma?", ":""),bchannels[i]);
				comma = true;
			}
		printf("\n");
	}
	printf("Beacon Miss Time: %d TUs\n", g->beacon_miss);
	printf("BT Coexist: %s\n", g->bt_coex?"On":"Off");
	printf("CCX Features: %s\n", g->ccx?"On":"Off");
	printf("Certificate Path: %s\n", g->cert_path);
	printf("Date Check: %s\n", g->date_check?"On":"Off");
	printf("Default Adhoc Channel: %d\n", g->def_adhoc_channel);
	printf("DFS Channels: ");
	switch( g->dfs_channels) {
		case DFS_OFF: printf("OFF\n");break;
		case DFS_FULL: printf("FULL\n");break;
		case DFS_OPTIMIZED: printf("Optimized\n");break;
		default: printf("invalid\n");
	}
	printf("FIPS Mode: %s\n", g->fips?"On":"Off");
	printf("Ignore Null SSID: %s\n", g->ignore_null_ssid?"On":"Off");
	printf("PMK Caching: ");
	switch(g->pmk){
		case STANDARD: printf("Standard\n"); break;
		case OPMK: printf("OPMK\n"); break;
		default: printf("invalid");
	}
	printf("Probe Delay: %d sec\n", g->probe_delay);
	printf("Regulatory Domain: ");
	switch(g->regdomain) {
		case REG_FCC: printf("FCC\n");break;
		case REG_ETSI: printf("ETSI\n");break;
		case REG_TELEC: printf("Japan\n");break;
		case REG_WW: printf("World\n");break;
		case REG_KCC: printf("Korea\n");break;
		case REG_CA: printf("Canada\n");break;
		case REG_FR: printf("France\n");break;
		case REG_GB: printf("United Kingdom\n");break;
		case REG_AU: printf("Australia\n");break;
		case REG_NZ: printf("New Zealand\n");break;
		case REG_CN: printf("China\n");break;
		case REG_BR: printf("Brazil\n");break;
		case REG_RU: printf("Russia\n");break;
		default: printf("invalid\n");
	}
	printf("Roam Period ms: %d ms\n",g->roam_periodms);
	printf("Roam Trigger: -%d dBm\n",g->roam_trigger);
	printf("RTS Threshold: %d bytes\n",g->rts);
	printf("Scan DFS Time: %d ms\n",g->scan_dfs);
	printf("TTLS Inner Method: ");
	switch(g->ttls_inner_method){
		case TTLS_AUTO: printf("AUTO\n");break;
		case TTLS_MSCHAPV2: printf("MSCHAPV2\n");break;
		case TTLS_MSCHAP:printf("MSCHAP\n");break;
		case TTLS_PAP:printf("PAP\n");break;
		case TTLS_CHAP:printf("CHAP\n");break;
		case TTLS_EAP_MSCHAPV2:printf("EAP MSCHAPV2\n");break;
		default: printf("invalid\n");
	}
	printf("UAPSD: %s\n", g->uapsd?"On":"Off");
	printf("WMM: %s\n", g->wmm?"On":"Off");
}
