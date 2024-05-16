#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dcal_api.h"
#include "sess_opts.h"

//#include "../../lib.local/libssh/include/libssh/libssh.h"

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	DCAL_ERR ret;
	int method;
	int rc;

	session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-3);
		goto cleanup;
	}

	application_name = "auth_method_test";

	if((ret = session_connect_with_opts(session, argc, argv, false))){
		printf("unable to setup connection\n");
		session = NULL;
		goto cleanup;
	}

	//determine what methods of auth are available.
	rc = dcal_get_auth_methods(session, &method);

	if (rc==DCAL_SUCCESS){
		printf("methods: %d\n", method);
		if(method & METHOD_PUBKEY)
			printf("public key authentication supported\n");
		if(method & METHOD_PASSWORD)
			printf("password authentication supported\n");
	}
	else
		printf("received %s\n",dcal_err_to_string(rc));

	ret = dcal_session_open(session);
	if (ret != DCAL_SUCCESS) {
			DBGERROR("Error connecting to host: %s\n", dcal_err_to_string(ret));
	} else {
		if (ret!= DCAL_SUCCESS) {
			printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		}
}

cleanup:
	return (ret!=DCAL_SUCCESS);

}
