#include <stdio.h>
#include "dcal_api.h"
#define DEBUG 1
#include "debug.h"
#include "session.h"
#include "dcal_internal_api.h"

extern int debug_to_stdout;
extern int debug_level;
const char *LRD_ERR_to_string( LRD_ERR code);
extern int dynamic_mem;

int main ()
{
	LRD_ERR ret;
	laird_session_handle session;

	REPORT_ENTRY_DEBUG;

	if (dynamic_mem)
	{
		printf("Library is set for dynamic memory allocation\n");
	}
	else
	{
		printf("Library is set for static memory allocation\n");
		ret = LRD_session_create( &session );
		if (ret==LRD_SUCCESS)
			printf("static - LRD_session_create() success\n");
		else
			printf("static - LRD_session_create() failed: %s\n", LRD_ERR_to_string(ret));

		//emulate the handle is in use
		((internal_session_handle)session)->state = 1;

		ret = LRD_session_create( &session );
		if (ret==LRD_HANDLE_IN_USE)
			printf("static - LRD_session_create() returned expected result\n");
		else
			printf("static - LRD_session_create() failed: %s\n", LRD_ERR_to_string(ret));

		ret = LRD_session_close( session );
		if (ret==LRD_SUCCESS)
			printf("static - LRD_session_close() success\n");
		else
			printf("static - LRD_session_close() failed: %s\n", LRD_ERR_to_string(ret));

		ret = LRD_session_close( session );
		if (ret==LRD_SUCCESS)
			printf("static - LRD_session_close() returned expected result\n");
		else
			printf("static - LRD_session_close() failed: %s\n", LRD_ERR_to_string(ret));

	}

	return REPORT_RETURN_DBG(0);
}
