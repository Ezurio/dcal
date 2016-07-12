#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

void print_int_as_4_bytes(char * str, int val)
{
	printf("%s: %d.%d.%d.%d\n", str, (val&0xff000000)>>24, (val&0xff0000)>>16, (val&0xff00)>>8, val&0xff);
}

const char * chipset_to_string(unsigned int cs)
{
	switch(cs)
	{
		case RADIOCHIPSET_SDC10: return "10"; break;
		case RADIOCHIPSET_SDC15: return "15"; break;
		case RADIOCHIPSET_SDC30: return "30"; break;
		case RADIOCHIPSET_SDC40L: return "40L"; break;
		case RADIOCHIPSET_SDC40NBT: return "40NBT"; break;
		case RADIOCHIPSET_SDC45: return "45"; break;
		case RADIOCHIPSET_SDC50: return "50"; break;
		case RADIOCHIPSET_NONE:
		default:
			return "no hardware detected";
	}
}

int main (int argc, char *argv[])
{
	int ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "profile_test";

	if((ret = session_connect_with_opts(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	laird_profile_handle profile;
	ret = dcal_wifi_profile_create(&profile);

	ret = dcal_wifi_profile_set_profilename(profile, "wifi");

	LRD_WF_SSID ssid={0};
	strcpy((char*)ssid.val, "TellMyWiFiLoveHer");
	ssid.len = strlen((char*)ssid.val);
	ret = dcal_wifi_profile_set_SSID( profile, &ssid);

	ret = dcal_wifi_profile_set_encrypt_std( profile, ES_WPA2);

	ret = dcal_wifi_profile_set_encryption( profile, ENC_AES);

	ret = dcal_wifi_profile_set_psk( profile, "YouAreWelcomeHere");

	ret = dcal_wifi_profile_set_clientname( profile, "clientname");

	dcal_wifi_profile_printf(profile);

	ret = dcal_wifi_profile_push( session, profile);
	printf("push return code: %d\n", ret);

	ret = dcal_wifi_profile_activate( session, profile);
	printf("activate return code: %d\n", ret);

	ret = dcal_wifi_profile_activate_by_name( session, "wifi");
	printf("activate return code: %d\n", ret);

	ret = dcal_wifi_profile_close_handle(profile);

	printf("profile closed - pulling now to verify\n");

	profile = NULL;

	ret = dcal_wifi_profile_pull(session, &profile, "wifi");

	if (ret==DCAL_SUCCESS)
		dcal_wifi_profile_printf(profile);
	else
		printf("Error in dcal_wifi_profile_pull(): %s\n", dcal_err_to_string(ret));

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
