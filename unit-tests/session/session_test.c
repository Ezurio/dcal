#include <stdio.h>
#include "dcal_api.h"
#define DEBUG 1
#include "debug.h"
#include "session.h"
#include "dcal_internal_api.h"

extern int debug_to_stdout;
extern int debug_level;
const char *DCAL_ERR_to_string( DCAL_ERR code);
extern int dynamic_mem;

int main ()
{
	DCAL_ERR ret;
	session_handle session;

	REPORT_ENTRY_DEBUG;

	if (dynamic_mem)
	{
		printf("Library is set for dynamic memory allocation\n");
	}
	else
	{
		printf("Library is set for static memory allocation\n");
		ret = dcal_session_create( &session );
		if (ret==DCAL_SUCCESS)
			printf("static - DCAL_session_create() success\n");
		else
			printf("static - DCAL_session_create() failed: %s\n", dcal_err_to_string(ret));

		//emulate the handle is in use
		((internal_session_handle)session)->state = 1;

		ret = dcal_session_create( &session );
		if (ret==DCAL_HANDLE_IN_USE)
			printf("static - DCAL_session_create() returned expected result\n");
		else
			printf("static - DCAL_session_create() failed: %s\n", dcal_err_to_string(ret));

		ret = dcal_session_close( session );
		if (ret==DCAL_SUCCESS)
			printf("static - DCAL_session_close() success\n");
		else
			printf("static - DCAL_session_close() failed: %s\n", dcal_err_to_string(ret));

		ret = dcal_session_close( session );
		if (ret==DCAL_SUCCESS)
			printf("static - DCAL_session_close() returned expected result\n");
		else
			printf("static - DCAL_session_close() failed: %s\n", dcal_err_to_string(ret));

	}

	return REPORT_RETURN_DBG(0);
}
