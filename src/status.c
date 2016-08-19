#include "buffer.h"
#include "debug.h"
#include "buffer.h"
#include "dcal_api.h"

#define BUF_SZ 2048

int build_query_status( flatcc_builder_t *B)
{

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_GETSTATUS)));
	ns(Command_end_as_root(B));

	return 0;
}

int dcal_device_status_get_settings( laird_session_handle s,
                                     char * profilename,
                                     size_t profilename_buflen,
                                     LRD_WF_SSID *ssid,
                                     unsigned char *mac,
                                     size_t mac_buflen)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG(DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);
	s_struct = &session->status;

	if (((profilename) && (profilename_buflen < strlen(s_struct->ProfileName)+1)))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	if ((mac) && (mac_buflen < MAC_SZ))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	time (&now);
	if ((CACHE_TIME) && (now - s_struct->timestamp > CACHE_TIME))
		return REPORT_RETURN_DBG(DCAL_DATA_STALE);

	if (profilename)
		strncpy(profilename, s_struct->ProfileName, profilename_buflen);

	if (ssid){
		memcpy(ssid->val, s_struct->ssid, SSID_SZ);
		ssid->len = s_struct->ssid_len;
	}

	if (mac)
		memcpy(mac, s_struct->mac, MAC_SZ);

	return REPORT_RETURN_DBG(0);
}

int dcal_device_status_get_ccx( laird_session_handle s,
                                       unsigned char *ap_ip,
                                       size_t ap_ip_buflen,
                                       char *ap_name,
                                       size_t ap_name_buflen,
                                       char * clientname,
                                       size_t clientname_buflen)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);
	s_struct = &session->status;

	time (&now);
	if ((CACHE_TIME) && (now - s_struct->timestamp > CACHE_TIME))
		return REPORT_RETURN_DBG(DCAL_DATA_STALE);

	if ((ap_ip) && (ap_ip_buflen < IP4_SZ))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	if ((ap_name) &&(ap_name_buflen < strlen(s_struct->ap_name)+1))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	if ((clientname) && (clientname_buflen < strlen(s_struct->clientName)+1))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	if (ap_ip)
		memcpy(ap_ip, s_struct->ap_ip, ap_ip_buflen);

	if (ap_name)
		strncpy(ap_name, s_struct->ap_name, ap_name_buflen);

	if (clientname)
		strncpy(clientname, s_struct->clientName, clientname_buflen);

	return REPORT_RETURN_DBG(0);
}

int dcal_device_status_get_ipv4( laird_session_handle s, unsigned char *ipv4, size_t buflen)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);

	s_struct = &session->status;

	time (&now);
	if ((CACHE_TIME) && (now - s_struct->timestamp > CACHE_TIME))
		return REPORT_RETURN_DBG(DCAL_DATA_STALE);

	if ((ipv4) && (buflen < IP4_SZ))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	if (ipv4)
		memcpy(ipv4, s_struct->ipv4, buflen);
	else
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);

	return REPORT_RETURN_DBG(0);
}

int dcal_device_status_get_ipv6_count( laird_session_handle s, size_t *count)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);

	s_struct = &session->status;

	if(!count)
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);

	*count = s_struct->num_ipv6_addr_strs;

	return REPORT_RETURN_DBG(DCAL_SUCCESS);
}

int dcal_device_status_get_ipv6_string_at_index( laird_session_handle s, unsigned int index, char *ipv6, size_t buflen)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);

	s_struct = &session->status;

	if (index > s_struct->num_ipv6_addr_strs)
		return REPORT_RETURN_DBG(DCAL_INDEX_OUT_OF_BOUNDS);

	// unlike other buflen checks, IP6_STR_SZ includes the trailing NULL
	if ((ipv6) && (buflen < IP6_STR_SZ))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	if (!ipv6)
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);

	time (&now);
	if ((CACHE_TIME) && (now - s_struct->timestamp > CACHE_TIME))
		return REPORT_RETURN_DBG(DCAL_DATA_STALE);

	strncpy(ipv6, s_struct->ipv6_strs[index], buflen);

	return REPORT_RETURN_DBG(0);
}

int dcal_device_status_get_connection( laird_session_handle s,
                                       unsigned int * cardstate,
                                       unsigned int * channel,
                                       int * rssi,
                                       unsigned char *ap_mac,
                                       size_t ap_mac_buflen)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);
	s_struct = &session->status;

	if((ap_mac) && (ap_mac_buflen < MAC_SZ))
		return REPORT_RETURN_DBG(DCAL_BUFFER_TOO_SMALL);

	time (&now);
if ((CACHE_TIME) && (now - s_struct->timestamp > CACHE_TIME))
		return REPORT_RETURN_DBG(DCAL_DATA_STALE);

	if (cardstate)
		*cardstate = s_struct->cardState;

	if (channel)
		*channel = s_struct->channel;

	if (rssi)
		*rssi = -s_struct->rssi;

	if (ap_mac)
		memcpy(ap_mac, s_struct->ap_mac, MAC_SZ);

	return REPORT_RETURN_DBG(0);
}

int dcal_device_status_get_connection_extended( laird_session_handle s,
                                       unsigned int *bitrate,
                                       unsigned int *txpower,
                                       unsigned int *dtim,
                                       unsigned int *beaconperiod)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle session=NULL;
	DCAL_STATUS_STRUCT * s_struct;
	time_t now;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);
	s_struct = &session->status;

	time (&now);
	if ((CACHE_TIME) && (now - s_struct->timestamp > CACHE_TIME))
		return REPORT_RETURN_DBG(DCAL_DATA_STALE);

	if (bitrate)
		*bitrate = s_struct->bitRate;

	if (txpower)
		*txpower = s_struct->txPower;

	if (dtim)
		*dtim = s_struct->dtim;

	if (beaconperiod)
		*beaconperiod = s_struct->beaconPeriod;

	return REPORT_RETURN_DBG(0);
}

int dcal_device_status_get_cache_timeout( unsigned int *timeout)
{
	if (!timeout)
		return DCAL_INVALID_PARAMETER;
	*timeout = CACHE_TIME;
	return 0;
}

int dcal_device_status_pull( laird_session_handle s)
{
	int ret = DCAL_SUCCESS;
	char buffer[BUF_SZ];
	size_t i, size = 0;
	flatcc_builder_t *B;
	ns(Status_table_t) status = NULL;
	internal_session_handle session=NULL;
	flatbuffers_thash_t buftype;
	DCAL_STATUS_STRUCT * s_struct;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(s))
		return REPORT_RETURN_DBG( DCAL_INVALID_HANDLE);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);
	s_struct = &session->status;

	B = &session->builder;

	size = BUF_SZ;
	memset(buffer, 0, BUF_SZ);
	build_query_status(B);

	size = flatcc_builder_get_buffer_size(B);
	assert(size <= BUF_SZ);
	flatcc_builder_copy_buffer(B, buffer, size);

	ret = lock_session_channel(session);
	if(ret)
		return REPORT_RETURN_DBG(ret);
	ret = dcal_send_buffer( session, buffer, size);

	if (ret != DCAL_SUCCESS) {
		unlock_session_channel(session);
		return REPORT_RETURN_DBG(ret);
	}

// get response
	size = BUF_SZ;
	ret = dcal_read_buffer( session, buffer, &size);
	unlock_session_channel(session);

	if (ret != DCAL_SUCCESS)
		return REPORT_RETURN_DBG(ret);

//is return buffer a status buffer?
	buftype = verify_buffer(buffer, size);

	if(buftype == ns(Handshake_type_hash))
		return handshake_error_code(ns(Handshake_as_root(buffer)));

	if(buftype != ns(Status_type_hash)){
		DBGERROR("could not verify status buffer.  Validated as: %s\n", buftype_to_string(buftype));
		return (DCAL_FLATBUFF_ERROR);
	}

	status = ns(Status_as_root(buffer));

	memset(s_struct, 0, sizeof(DCAL_STATUS_STRUCT));
	s_struct->cardState = ns(Status_cardState(status));
	strncpy(s_struct->ProfileName, ns(Status_ProfileName(status)),NAME_SZ);
	s_struct->ssid_len =flatbuffers_uint8_vec_len(ns(Status_ssid(status)));
	if (s_struct->ssid_len > SSID_SZ)
		return DCAL_FLATBUFF_ERROR;
	memcpy(s_struct->ssid, ns(Status_ssid(status)), s_struct->ssid_len);
	s_struct->channel = ns(Status_channel(status));
	s_struct->rssi = ns(Status_rssi(status));
	strncpy(s_struct->clientName, ns(Status_clientName(status)), NAME_SZ);
	memcpy(s_struct->mac, ns(Status_mac(status)), MAC_SZ);
	memcpy(s_struct->ipv4, ns(Status_ip(status)), IP4_SZ);
	memcpy(s_struct->ap_mac, ns(Status_AP_mac(status)), MAC_SZ);
	memcpy(s_struct->ap_ip, ns(Status_AP_ip(status)), IP4_SZ);
	strncpy(s_struct->ap_name, ns(Status_AP_name(status)), NAME_SZ);
	s_struct->bitRate = ns(Status_bitRate(status))/2;
	s_struct->txPower = ns(Status_txPower(status));
	s_struct->beaconPeriod = ns(Status_beaconPeriod(status));
	s_struct->dtim = ns(Status_dtim(status));

	flatbuffers_string_vec_t ipaddresses = ns(Status_ipv6(status));
	size_t num_ips = flatbuffers_string_vec_len(ipaddresses);

	char * tmp = realloc(s_struct->ipv6_strs, num_ips * IP6_STR_SZ);
	if (tmp==NULL)
		return DCAL_NO_MEMORY;
	s_struct->ipv6_strs = (ipv6_str_type *)tmp;
	s_struct->num_ipv6_addr_strs = num_ips;

	for (i=0; (i < num_ips); i++)
		strncpy(s_struct->ipv6_strs[i], flatbuffers_string_vec_at(ipaddresses,i),IP6_STR_SZ);

	time(&s_struct->timestamp);
	return REPORT_RETURN_DBG (ret);
}

