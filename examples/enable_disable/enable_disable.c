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
		{"disable", no_argument, NULL, 'D'},
		{NULL, 0, NULL, 0}
	};
	int c, optidx = 0;
	bool enable = true;

	while ((c=getopt_long(2, argv,"D",longopt, &optidx)) != -1){
		switch(c) {
			case 'D':
				enable = false;
				break;
		}
	}

	printf("setting %s\n", enable?"enable":"disable");

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "enable_test";

	session_connect_with_opts(session, argc, argv, true);
	#if 0
	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}
	#endif

// device interaction

	if (enable)
		ret = dcal_wifi_enable( session );
	else
		ret = dcal_wifi_disable( session );

	if (ret != DCAL_SUCCESS)
		printf("unable to set ");
	else 
		printf("device is now ");
	
		printf("%s\n", enable?"enable":"disable");

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
