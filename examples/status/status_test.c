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

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction

	unsigned int cache_time;
	dcal_device_status_get_cache_timeout(&cache_time);
	dcal_device_status_pull( session );
	printf("status pulled from device\n");
	char profilename[NAME_SZ];
	ret = dcal_device_status_get_settings( session, profilename, NAME_SZ, NULL, NULL, 0);
	if (ret != DCAL_SUCCESS)
		printf("unable to get status: %d\n", ret);
	else 
		printf("\tProfile Name: %s\n", profilename);

	printf ("Checking for data going stale - should do so in %d seconds\n", cache_time);
	for (cache_time+=2;cache_time;cache_time--){
		printf("%d..",cache_time);
		fflush(stdout);
		sleep(1);
		}

	if ((ret=dcal_device_status_get_settings( session, NULL, 0, NULL, NULL, 0)==DCAL_DATA_STALE))
		printf("\ncorrectly received stale error return\n");
	else
		printf("\nincorrect return code: %d\n", ret);

	dcal_device_status_pull( session );
	printf("status pulled from device again\n");

	LRD_WF_SSID ssid;
	unsigned char mac[MAC_SZ];
	ret = dcal_device_status_get_settings( session, profilename, NAME_SZ, &ssid, mac, MAC_SZ);

	printf("Status:\n");
	if (ret != DCAL_SUCCESS)
		printf("unable to get status: %d\n", ret);
	else {
		printf("\tProfile Name: %s\n", profilename);
		// TODO - check id SSID is all ascii and print as hex if not
		printf("\tSSID: %s\n", ssid.val);
		printf("\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		              mac[0],mac[1],mac[2],
		              mac[3],mac[4],mac[5]);
	}

	unsigned char ap_ip[IP4_SZ];
	char ap_name[NAME_SZ];
	char clientname[NAME_SZ];
	ret = dcal_device_status_get_ccx( session, ap_ip, IP4_SZ, ap_name, NAME_SZ, clientname, NAME_SZ);
	printf("CCX status:\n");
	if (ret != DCAL_SUCCESS)
		printf("unable to get CCX status: %d\n", ret);
	else {
		printf("\tAP Name: %s\n", ap_name);
		printf("\tAP IP: %d.%d.%d.%d\n",ap_ip[0],ap_ip[1],
		                              ap_ip[2],ap_ip[3]);
		printf("\tDevice Name: %s\n", clientname);
	}

	unsigned char ipv4[IP4_SZ];
	ret = dcal_device_status_get_ipv4(session, ipv4, IP4_SZ);
	printf("IPv4:\n");
	if (ret != DCAL_SUCCESS)
		printf("unable to get IPv4 status: %d\n", ret);
	else {
		printf("\tIP: %d.%d.%d.%d\n",ipv4[0],ipv4[1],
		                           ipv4[2],ipv4[3]);
	}

	size_t i, count;
	ret = dcal_device_status_get_ipv6_count(session, &count);
	if (ret != DCAL_SUCCESS)
		printf("unable to get IPv6 address count: %d\n", ret);
	else if (count > 0)
	{
		printf("IPv6:\n");
		ipv6_str_type * ipv6addr = malloc(count*sizeof(ipv6_str_type));
		if (ipv6addr == NULL)
			printf("unable to allocate memory for IPv6 addresses\n");
		else {
			for (i=0; i<count; i++){
				ret = dcal_device_status_get_ipv6_string_at_index(session, i, ipv6addr[i], sizeof(ipv6_str_type));
				if (ret)
					printf("unable to get ipv6 address at index %zu.  Error: %d\n",i,ret);
				else
					printf("\tIPv6: %s\n", ipv6addr[i]);
			}
			free(ipv6addr);
		}
	}

	unsigned int cardstate;
	unsigned int channel;
	int rssi;
	unsigned char ap_mac[MAC_SZ];
	ret = dcal_device_status_get_connection(session, &cardstate, &channel, &rssi, ap_mac, MAC_SZ);
	printf("Connection status:\n");
	if (ret != DCAL_SUCCESS)
		printf("unable to get connection status: %d\n", ret);
	else {
		printf("\tStatus: %s\n",cardState_to_string(cardstate));
		printf("\tChannel: %d\n", channel);
		printf("\trssi: %d\n", rssi);
		printf("\tAP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		              ap_mac[0],ap_mac[1],ap_mac[2],
		              ap_mac[3],ap_mac[4],ap_mac[5]);
	}

	unsigned int bitrate;
	unsigned int txpower;
	unsigned int dtim;
	unsigned int beaconperiod;
	ret = dcal_device_status_get_connection_extended(session, &bitrate, &txpower, &dtim, &beaconperiod);
	printf("extended connection status:\n");
	if (ret != DCAL_SUCCESS)
		printf("unable to get extended connection status: %d\n", ret);
	else {
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
