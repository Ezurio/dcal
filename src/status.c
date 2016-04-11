#include "buffer.h"
#include "debug.h"

#define BUF_SZ 1024

DCAL_ERR dcal_device_status( laird_session_handle s, DCAL_STATUS_STRUCT * s_struct)
{
	ns(Status_table_t) status;
	DCAL_ERR ret = DCAL_SUCCESS;
	char buffer[BUF_SZ];
	size_t size;
	flatcc_builder_t builder;
	void * handshake_buffer;

	REPORT_ENTRY_DEBUG;

	if ((s==NULL) || (s_struct==NULL)){
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);
	}

	flatcc_builder_init(&builder);
	flatcc_builder_reset(&builder);
	ns(Handshake_start_as_root(&builder));
	ns(Handshake_magic_add(&builder, ns(Magic_HELLO)));
	ns(Handshake_ip_create_str(&builder, "127.0.0.1"));
	ns(Handshake_end_as_root(&builder));

	handshake_buffer = flatcc_builder_get_direct_buffer(&builder, &size);
	if(handshake_buffer==NULL)
		return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);

	flstcc_builder_clear(&builder);

// send request
	ret = dcal_send_buffer( s, handshake_buffer, size);

	if(ret!=DCAL_SUCCESS)
		return REPORT_RETURN_DBG(ret);

// get response
	size = BUF_SZ;
	ret = dcal_read_buffer( s, buffer, &size);

	if (ret != DCAL_SUCCESS)
		return REPORT_RETURN_DBG(ret);
	
	if((ret=ns(Status_verify_as_root(buffer, size, ns(Status_identifier))))){
		DBGERROR("could not verify buffer, got %s\n", flatcc_verify_error_string(ret));
		return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
	}

	if(!(status = ns(Status_as_root(buffer)))){
		DBGERROR("Buffer is not a status buffer\n");
		return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
	}
	memset(s_struct, 0, sizeof(DCAL_STATUS_STRUCT));
	s_struct->cardState = ns(Status_cardState(status));
	strncpy(s_struct->ProfileName, ns(Status_ProfileName(status)),NAME_SZ);
	strncpy(s_struct->ssid, ns(Status_ssid(status)), SSID_SZ);
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

	return REPORT_RETURN_DBG (ret);
}

