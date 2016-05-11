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

	DCAL_STATUS_STRUCT status;
	ret = dcal_device_status( session, &status );
	if (ret != DCAL_SUCCESS)
		printf("unable to read status\n");
	else {
		printf("Status:\n");
		printf("\tStatus: %s\n",cardState_to_string(status.cardState));
		printf("\tProfile Name: %s\n", status.ProfileName);
		printf("\tSSID: %s\n", status.ssid);
		printf("\tChannel: %d\n", status.channel);
		printf("\trssi: %d\n", status.rssi);
		printf("\tDevice Name: %s\n", status.clientName);
		printf("\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		              status.mac[0],status.mac[1],status.mac[2],
		              status.mac[3],status.mac[4],status.mac[5]);

		printf("\tIP: %d.%d.%d.%d\n",status.ipv4[0],status.ipv4[1],
		                           status.ipv4[2],status.ipv4[3]);
		printf("\tIPv6: %s\n", status.ipv6);
		printf("\tAP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		              status.ap_mac[0],status.ap_mac[1],status.ap_mac[2],
		              status.ap_mac[3],status.ap_mac[4],status.ap_mac[5]);
		printf("\tAP IP: %d.%d.%d.%d\n",status.ap_ip[0],status.ap_ip[1],
		                              status.ap_ip[2],status.ap_ip[3]);
		printf("\tBit Rate: %d\n", status.bitRate);
		printf("\tTx Power: %d\n", status.txPower);
		printf("\tBeacon Period: %d\n", status.beaconPeriod);
		printf("\tDTIM: %d\n", status.dtim);
	}

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
