#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

const char * cardState_to_string(unsigned int cs)
{
	switch(cs)
	{
		case 0: return "Not Inserted"; break;
		case 1: return "Not Associated"; break;
		case 2: return "Associated"; break;
		case 3: return "Authenticated"; break;
		case 4: return "FCC Test"; break;
		case 5: return "Not Laird"; break;
		case 6: return "disabled"; break;
		case 7: return "error"; break;
		case 8: return "AP Mode"; break;
		default: return "unknown cardState";
	}
}

int main (int argc, char *argv[])
{
	DCAL_ERR ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "status_test";

	if((ret = session_connect_with_opts(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction

	unsigned int cache_time;
	dcal_device_status_get_cache_timeout(&cache_time);

	dcal_device_status_pull( session );
	for (cache_time+=2;cache_time;cache_time--){
		printf("%d..",cache_time);
		fflush(stdout);
		sleep(1);
		}

	if ((ret=dcal_device_status_get_settings( session, NULL, NULL, NULL, NULL)==DCAL_DATA_STALE))
		printf("\ncorrectly received stale error return\n");
	else
		printf("\nincorrect return code: %d\n", ret);

	dcal_device_status_pull( session );

	char profilename[NAME_SZ];
	char ssid[SSID_SZ];
	unsigned int ssid_len;
	char clientname[NAME_SZ];
	ret = dcal_device_status_get_settings( session, profilename, ssid, &ssid_len, clientname);

	if (ret != DCAL_SUCCESS)
		printf("unable to get settings: %d\n", ret);

	unsigned int cardstate;
	unsigned int channel;
	int rssi;
	unsigned char mac[MAC_SZ];
	unsigned char ipv4[IP4_SZ];
	char ipv6[IP6_STR_SZ];
	unsigned char ap_mac[MAC_SZ];
	unsigned char ap_ip[IP4_SZ];
	char ap_name[NAME_SZ];
	unsigned int bitrate;
	unsigned int txpower;
	unsigned int dtim;
	unsigned int beaconperiod;

	ret = dcal_device_status_get_connection( session, &cardstate, &channel, &rssi, mac, ipv4, ipv6, ap_mac, ap_ip, ap_name, &bitrate, &txpower, &dtim, &beaconperiod);

	if (ret != DCAL_SUCCESS)
		printf("unable to read status\n");
	else {
		printf("Status:\n");
		printf("\tStatus: %s\n",cardState_to_string(cardstate));
		printf("\tProfile Name: %s\n", profilename);
		printf("\tSSID: %s\n", ssid);
		printf("\tChannel: %d\n", channel);
		printf("\trssi: %d\n", rssi);
		printf("\tDevice Name: %s\n", clientname);
		printf("\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		              mac[0],mac[1],mac[2],
		              mac[3],mac[4],mac[5]);

		printf("\tIP: %d.%d.%d.%d\n",ipv4[0],ipv4[1],
		                           ipv4[2],ipv4[3]);
		printf("\tIPv6: %s\n", ipv6);
		printf("\tAP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		              ap_mac[0],ap_mac[1],ap_mac[2],
		              ap_mac[3],ap_mac[4],ap_mac[5]);
		printf("\tAP IP: %d.%d.%d.%d\n",ap_ip[0],ap_ip[1],
		                              ap_ip[2],ap_ip[3]);
		printf("\tBit Rate: %d\n", bitrate);
		printf("\tTx Power: %d\n", txpower);
		printf("\tBeacon Period: %d\n", beaconperiod);
		printf("\tDTIM: %d\n", dtim);
	}

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
