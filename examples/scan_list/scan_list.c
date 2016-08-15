#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sdc_sdk_legacy.h"
#include "dcal_api.h"
#include "sess_opts.h"

void print_securityMask( int securityMask)
{
typedef struct _priority {
	WEPTYPE type;
	char *str;
	} priority_item;

	priority_item priority[]={
		{ WAPI_CERT, "WAP_CERT" },
		{ WAPI_PSK, "WAPI_PSK" },
		{ WPA2_AES, "WPA2_AES" },
		{ CCKM_AES, "CCKM_AES" },
		{ WPA_AES, "WPA_AES" },
		{ WPA2_PSK, "WPA2_PSK" },
		{ WPA_PSK_AES, "WPA_PSK_AES" },
		{ WPA2_TKIP, "WPA2_TKIP" },
		{ CCKM_TKIP, "CCKM_TKIP" },
		{ WPA_TKIP, "WPA_TKIP" },
		{ WPA2_PSK_TKIP, "WPA2_PSK_TKIP" },
		{ WPA_PSK, "WPA_PSK" },
		{ WEP_ON, "WEP_ON" },
		{ WEP_AUTO, "WEP_AUTO" },
		{ WEP_OFF, "WEP_OFF" },
		{ WEP_AUTO_CKIP, "WEP_AUTO_CKIP" },
		{ WEP_CKIP, "WEP_CKI" }
	};
	char space = 0;
	unsigned int i;
	for (i=0; i < sizeof(priority)/sizeof(priority_item); i++){
		if (securityMask & (1 << priority[i].type)){
			if (space)
				printf(" ");
			space = 1;
			printf("%s", priority[i].str);
		}
	}
}

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	DCAL_ERR ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "scan_list";

	if((ret = session_connect_with_opts(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

#define BUFLEN 32
// device interaction

	size_t elements = 0;
	ret = dcal_wifi_pull_scan_list(session, &elements);
	if(!ret) ret = dcal_wifi_pull_scan_list(session, &elements);
	if(!ret) ret = dcal_wifi_pull_scan_list(session, &elements);

	printf("pulled %lu elements\n", elements);

#define MACSZ 6
	int i;
	LRD_WF_SSID ssid;
	unsigned char bssid[MACSZ];
	int channel;
	int rssi;
	int securityMask;
	LRD_WF_BSSTYPE bssType;
	for (i=0; i< elements; i++) {

		ret = dcal_wifi_get_scan_list_entry_ssid( session, i, &ssid);
		if (!ret)
			ret = dcal_wifi_get_scan_list_entry_bssid( session, i, bssid, MACSZ);
		if (!ret)
			ret = dcal_wifi_get_scan_list_entry_channel( session, i, &channel);
		if (!ret)
			ret = dcal_wifi_get_scan_list_entry_rssi( session, i, &rssi);
		if (!ret)
			ret = dcal_wifi_get_scan_list_entry_securityMask( session, i, &securityMask);
		if (!ret)
			ret = dcal_wifi_get_scan_list_entry_type( session, i, &bssType);
		printf("--------------------\n");
		if (ret) {
			printf("error getting scan_list_entry item: %s\n", dcal_err_to_string(ret));
		} else {
			printf("ssid: %s\n", ssid.val);
			printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
			              bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
			printf("channel: %d\n", channel);
			printf("rssi: %d\n", rssi);
			printf("bss Type: %s\n", (bssType==INFRASTRUCTURE?"Infrastructure":"Adhoc"));
			printf("security: ");
			print_securityMask(securityMask);
			printf("\n");
		}
	}

	dcal_session_close(session);

cleanup:
	return (ret!=DCAL_SUCCESS);

}
