#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	int ret;

	session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "cli_test";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

	if ((optind > argc) || (argv[optind]==NULL))
	{
		ret = DCAL_INVALID_PARAMETER;
		printf("missing filename of file to send to WB's sdc_cli command\n");
		goto cleanup;
	}

	printf("sending file: %s\n", argv[optind]);

	ret = dcal_process_cli_command_file(session, argv[optind]);

	if (ret) printf("error in cli_command_file(): %s\n",dcal_err_to_string(ret));

cleanup:
	if(session)
		dcal_session_close(session);
	return (ret!=DCAL_SUCCESS);

}
