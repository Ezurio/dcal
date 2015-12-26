#include "debug.h"

// need a function to test makefile

LRD_API_ERR foobar ()
{
	LRD_API_ERR ret = LRD_API_SUCCESS;
	REPORT_ENTRY_DEBUG;

	return REPORT_RETURN_DBG(ret);
}
