#include <stdio.h>
#include <stdlib.h>
#include "dcal_api.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}
int main ()
{
	LRD_ERR ret;

	char cert[cert_size];

	laird_session_handle session;

	ret = LRD_session_create( &session );
	if (ret!= LRD_SUCCESS) {
		printf("received %s at line %d\n", LRD_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

	ret = LRD_setip( session, "192.168.2.131" );
	if (ret!= LRD_SUCCESS) {
		printf("received %s at line %d\n", LRD_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

	ret = LRD_setkey( session, cert, cert_size);
	if (ret!= LRD_SUCCESS) {
		printf("received %s at line %d\n", LRD_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

	ret =  LRD_session_open (  session );
	if (ret!= LRD_SUCCESS) {
		printf("received %s at line %d\n", LRD_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

// device interaction

	ret = LRD_session_close( session );
	if (ret!= LRD_SUCCESS) {
		printf("received %s at line %d\n", LRD_ERR_to_string(ret), __LINE__-2);
//		goto cleanup;
	}

//cleanup:

	return (ret!=LRD_SUCCESS);

}
