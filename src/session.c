#include "stdlib.h"
#include "lrd_internal_api.h"

LRD_API_ERR LRD_API_create_session( laird_session_handle * session)
{
	LRD_API_ERR ret = LRD_API_NOT_IMPLEMENTED;

	internal_session_handle * handle = (internal_session_handle*) session;

	REPORT_ENTRY_DEBUG;

	if (handle==NULL)
		ret = LRD_API_INVALID_PARAMETER;

	return REPORT_RETURN_DBG(ret);
}

LRD_API_ERR LRD_API_setip( laird_session_handle * session, FQDN address )
{
	LRD_API_ERR ret = LRD_API_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;

	return REPORT_RETURN_DBG(ret);
}

LRD_API_ERR LRD_API_setkey( laird_session_handle * session, char * keydata, int size)
{
	LRD_API_ERR ret = LRD_API_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;

	return REPORT_RETURN_DBG(ret);
}

LRD_API_ERR LRD_API_session_open ( laird_session_handle * session )
{
	LRD_API_ERR ret = LRD_API_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;

	return REPORT_RETURN_DBG(ret);
}

LRD_API_ERR LRD_API_session_close( laird_session_handle * session)
{
	LRD_API_ERR ret = LRD_API_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;

	return REPORT_RETURN_DBG(ret);
}


