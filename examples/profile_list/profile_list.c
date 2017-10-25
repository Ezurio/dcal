#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dcal_api.h"
#include "sess_opts.h"


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

	application_name = "profile_list";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

#define BUFLEN 32
// device interaction
	size_t elements = 0;
	size_t buflen=BUFLEN;
	// calling multiple times one so I can run against valgrind to verify
	// no memory issues
	ret = dcal_wifi_pull_profile_list(session, &elements);
	if(!ret) ret = dcal_wifi_pull_profile_list(session, &elements);
	if(!ret) ret = dcal_wifi_pull_profile_list(session, &elements);

	printf("pulled %zu elements\n", elements);
	int i;
	char profilename[BUFLEN];
	bool active;
	bool autoprofile;
	for (i=0; i< elements; i++) {
		ret = dcal_wifi_get_profile_list_entry_profilename( session, i, profilename, buflen);
		if(!ret) ret = dcal_wifi_get_profile_list_entry_autoprofile( session, i,  &autoprofile);
		if(!ret) ret = dcal_wifi_get_profile_list_entry_active( session, i, &active);
		if(ret)
			printf("error getting list entry: %s\n", dcal_err_to_string(ret));
		else
			printf("%d: %32s\tautoprofile: %s\t%s\n", i+1, profilename, (autoprofile?"on":"off"), (active?"active profile":""));
	}

	dcal_session_close(session);
cleanup:
	return (ret!=DCAL_SUCCESS);

}
