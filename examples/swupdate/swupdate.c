#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	int ret, i, j, len;
	char parameter[256];

	session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "sw_update";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		common_usage(application_name);
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

	if ((optind > argc) || (argv[optind]==NULL))
	{
		ret = DCAL_INVALID_PARAMETER;
		printf("missing parameters for swupdate\n");
		goto cleanup;
	}

	len = strlen(argv[optind]);
	assert(len < 256);
	assert(argv[optind][len-1] != '\\');

	for(i=j=0; i<strlen(argv[optind]); i++){
		if(argv[optind][i] == '\\' && argv[optind][i+1] == '-')
			++i;
		parameter[j++] = argv[optind][i];
	}
	parameter[j] = '\0';
	ret = dcal_do_swupdate(session, parameter);
	if (ret) printf("error in sw_update(): %s\n",dcal_err_to_string(ret));

cleanup:
	if(session)
		dcal_session_close(session);
	return (ret!=DCAL_SUCCESS);

}
