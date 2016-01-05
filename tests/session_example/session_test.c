#include <stdio.h>
#include <stdlib.h>
#include "lrd_remote_api.h"

#define cert_size 1024

int main ()
{
	LRD_API_ERR ret;

	char cert[cert_size];

	laird_session_handle *session =
	           (laird_session_handle*)malloc(sizeof(laird_profile_handle));

	if (session==NULL) {
		printf("Error - unable to malloc\n");
		return -1;
	}

	ret = LRD_API_create_session( session );
	if (ret!= LRD_API_SUCCESS) {
		printf("received %s at line %d\n", LRD_API_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

	ret = LRD_API_setip( session, "192.168.2.131" );
	if (ret!= LRD_API_SUCCESS) {
		printf("received %s at line %d\n", LRD_API_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

	ret = LRD_API_setkey( session, cert, cert_size);
	if (ret!= LRD_API_SUCCESS) {
		printf("received %s at line %d\n", LRD_API_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

	ret =  LRD_API_session_open (  session );
	if (ret!= LRD_API_SUCCESS) {
		printf("received %s at line %d\n", LRD_API_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

// device interaction

	ret = LRD_API_session_close( session );
	if (ret!= LRD_API_SUCCESS) {
		printf("received %s at line %d\n", LRD_API_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

//cleanup:
	free(session);

	return (ret!=LRD_API_SUCCESS);

}
