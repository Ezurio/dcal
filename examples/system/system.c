#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>

#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	DCAL_ERR ret;

	laird_session_handle session;

	static struct option longopt[] = {
		{"system restart", no_argument, NULL, 'S'},
		{NULL, 0, NULL, 0}
	};
	int c, optidx = 0;
	bool wifireset = true;

	while ((c=getopt_long(2, argv,"S",longopt, &optidx)) != -1){
		switch(c) {
			case 'S':
				wifireset = false;
				break;
		}
	}

	printf("issue reset of %s\n", wifireset?"wifi radio":"system");

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "system_test";

	session_connect_with_opts(session, argc, argv);

// device interaction

	if (wifireset)
		ret = dcal_wifi_restart( session );
	else
		ret = dcal_system_restart( session );

	if (ret != DCAL_SUCCESS)
		printf("unable to reset ");
	else 
		printf("device is now reset: ");
	
		printf("%s\n", wifireset?"wifi radio":"system");

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
