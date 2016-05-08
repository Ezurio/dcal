#include "buffer.h"
#include "debug.h"
#include "dcal_api.h"

#define BUF_SZ 2048

int build_query_status( flatcc_builder_t *B, char *buf, size_t *size)
{

	flatcc_builder_reset(B);

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_GETSTATUS)));
	ns(Command_ref_t) command = ns(Command_end(B));

	ns(Any_union_ref_t) any;
	any.Command = command;
	any.type = ns(Any_Command);

	ns(Payload_start_as_root(B));
	ns(Payload_message_add(B, any));
	ns(Payload_end_as_root(B));

	flatcc_builder_copy_buffer(B, buf, *size);
	*size =flatcc_builder_get_buffer_size(B);

	return 0;
}

DCAL_ERR dcal_device_status( laird_session_handle s, DCAL_STATUS_STRUCT * s_struct)
{
	DCAL_ERR ret = DCAL_SUCCESS;
	char buffer[BUF_SZ];
	size_t i, size = 0;
	flatcc_builder_t *B;
	ns(Payload_table_t) payload;
	ns(Any_union_type_t) any;
	ns(Status_table_t) status = NULL;
	internal_session_handle session=NULL;

	REPORT_ENTRY_DEBUG;

	if ((s==NULL) || (s_struct==NULL)){
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);
	}

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);

	B = &session->builder;

	size = BUF_SZ;
	memset(buffer, 0, BUF_SZ);
	build_query_status(B, buffer, &size);

	ret = dcal_send_buffer( session, buffer, size);

// get response
	size = BUF_SZ;
	ret = dcal_read_buffer( session, buffer, &size);

	if (ret != DCAL_SUCCESS)
		return REPORT_RETURN_DBG(ret);

//is return buffer a status buffer?

// verify is status buffer
	if((ret=ns(Payload_verify_as_root(buffer, size)))){
		DBGERROR("could not verify status buffer.  Size is %zu. Got %s\n", size, flatcc_verify_error_string(ret));
		return (DCAL_FLATBUFF_ERROR);
	}

	if (!(payload = ns(Payload_as_root(buffer)))) {
		DBGERROR("Not a Payload\n");
		return DCAL_FLATBUFF_ERROR;
	}

	any = ns(Payload_message_type(payload));

	if (any == ns(Any_Status))
		status = ns(Payload_message(payload));
	else{
		DBGERROR("Payload message was not a status\n");
		return DCAL_FLATBUFF_ERROR;
	}

	memset(s_struct, 0, sizeof(DCAL_STATUS_STRUCT));
	s_struct->cardState = ns(Status_cardState(status));
	strncpy(s_struct->ProfileName, ns(Status_ProfileName(status)),NAME_SZ);
	s_struct->ssid_len = ns(Status_ssid_len(status));
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
	s_struct->bitRate = ns(Status_bitRate(status))/2;
	s_struct->txPower = ns(Status_txPower(status));
	s_struct->beaconPeriod = ns(Status_beaconPeriod(status));
	s_struct->dtim = ns(Status_dtim(status));

//TODO determine how to present a variable number of addresses
	flatbuffers_string_vec_t ipaddresses = ns(Status_ipv6(status));
	size_t num_ips = flatbuffers_string_vec_len(ipaddresses);
	for (i=0; ((i < num_ips) && i < 1); i++)
		strncpy(s_struct->ipv6, flatbuffers_string_vec_at(ipaddresses,i),IP6_STR_SZ);

	return REPORT_RETURN_DBG (ret);
}

