#include <stdio.h>
#include <stdlib.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}
int main (int argc, char * argv[])
{
	DCAL_ERR ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "session_test";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	printf("session established\n");

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
