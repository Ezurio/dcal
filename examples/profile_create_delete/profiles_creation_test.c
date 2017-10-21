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

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	laird_profile_handle profile;
	size_t elements = 0;
	#define BUFLEN 32
	size_t buflen=BUFLEN;

	ret = dcal_wifi_pull_profile_list(session, &elements);

	int i;
	char profilename[BUFLEN+1] = {0};
	printf("profile count: %zu\n", elements);
	for (i=0; i<elements; i++) {
		ret = dcal_wifi_get_profile_list_entry_profilename(session, i, profilename, buflen);
		if(ret){
			printf("error getting list entry: %s\n", dcal_err_to_string(ret));
			goto cleanup;
		}
		else
			printf("%d:\t%s\n", i, profilename);
		}

	for (i=0; i<5; i++){
		ret = dcal_wifi_profile_create(&profile);
		sprintf(profilename,"%s%d","profile", i);
		ret = dcal_wifi_profile_set_profilename(profile, profilename);
		if(ret){
			printf("error setting profile name: %s\n", dcal_err_to_string(ret));
			goto cleanup;
		}
		printf("Profile name: ->%s<-\n", profilename);
		printf("creating profile %s: ", profilename);
		ret = dcal_wifi_profile_push( session, profile );
		printf("%s\n", dcal_err_to_string(ret));
		if(ret)
			goto cleanup;

		ret = dcal_wifi_profile_close_handle(profile);
		if(ret) {
			printf("error closing profile handle: %s", dcal_err_to_string(ret));
			goto cleanup;
		}

		printf("deleting profile %s: ", profilename);
		ret = dcal_wifi_profile_delete_from_device(session, profilename);
		printf("%s\n", dcal_err_to_string(ret));
		if(ret)
			goto cleanup;
	}

	printf("profile count: %zu\n", elements);
	for (i=0; i<elements; i++) {
		ret = dcal_wifi_get_profile_list_entry_profilename(session, i, profilename, buflen);
		if(ret){
			printf("error getting list entry: %s\n", dcal_err_to_string(ret));
			goto cleanup;
		}
		else
			printf("%d:\t%s\n", i, profilename);
		}
cleanup:
	dcal_session_close( session );

	return (ret!=DCAL_SUCCESS);

}
