#include "stdlib.h"
#include "lrd_internal_api.h"

LRD_ERR LRD_session_create( laird_session_handle * session)
{
	LRD_ERR ret = LRD_NOT_IMPLEMENTED;
	internal_session_handle handle;

	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = LRD_INVALID_PARAMETER;

	else {
		handle = (internal_session_handle) malloc(sizeof(internal_session_struct));

		if (handle==NULL)
			ret = LRD_INVALID_PARAMETER;
		else
			*session = (pvoid)handle;
	}

	return REPORT_RETURN_DBG(ret);
}

LRD_ERR LRD_setip( laird_session_handle session, FQDN address )
{
	LRD_ERR ret = LRD_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;
	if (session==NULL)
		ret = LRD_INVALID_PARAMETER;

	return REPORT_RETURN_DBG(ret);
}

LRD_ERR LRD_setkey( laird_session_handle session, char * keydata, int size)
{
	LRD_ERR ret = LRD_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (keydata==NULL) || (size==0))
		ret = LRD_INVALID_PARAMETER;

	return REPORT_RETURN_DBG(ret);
}

LRD_ERR LRD_session_open ( laird_session_handle session )
{
	LRD_ERR ret = LRD_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;
	if (session==NULL)
		ret = LRD_INVALID_PARAMETER;

	return REPORT_RETURN_DBG(ret);
}

LRD_ERR LRD_session_close( laird_session_handle session)
{
	LRD_ERR ret = LRD_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;
	if (session==NULL)
		ret = LRD_INVALID_PARAMETER;
	else
		free(session);

	return REPORT_RETURN_DBG(ret);
}


