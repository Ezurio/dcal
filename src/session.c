#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_internal_api.h"
#include "session.h"

#ifdef STATIC_MEM

static internal_session_struct static_session = { 0 };

#else

#include "lists.h"
static pointer_list * sessions = NULL;

#endif

static DCAL_ERR get_session_handle( laird_session_handle * session )
{
	internal_session_handle handle=NULL;
	DCAL_ERR ret = DCAL_SUCCESS;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;

	else {
	#ifdef STATIC_MEM
		if (static_session.valid)
			ret = DCAL_HANDLE_IN_USE;
		else {
			handle = &static_session;
			memset(handle, 0, sizeof(internal_session_struct));
		}
	#else
		handle = (internal_session_handle) malloc(sizeof(internal_session_struct));
		if (handle==NULL)
			ret = DCAL_NO_MEMORY;
		else {
			memset(handle, 0, sizeof(internal_session_struct));
			ret = add_to_list(&sessions, handle);
		}
	#endif
	}
	if (ret==DCAL_SUCCESS)
		*session = handle;

	return ret;
}

DCAL_ERR dcal_session_create( laird_session_handle * session)
{
	DCAL_ERR ret = DCAL_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;

	else
		ret = get_session_handle( session );

	return REPORT_RETURN_DBG(ret);
}

DCAL_ERR dcal_set_ip( laird_session_handle session, FQDN address )
{
	DCAL_ERR ret = DCAL_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;
	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;

	return REPORT_RETURN_DBG(ret);
}

DCAL_ERR dcal_set_key( laird_session_handle session, char * keydata, int size)
{
	DCAL_ERR ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (keydata==NULL) || (size==0))
		ret = DCAL_INVALID_PARAMETER;

	else
#ifdef STATIC_MEM
	ret = (((internal_session_handle)session)->valid?DCAL_SUCCESS:DCAL_INVALID_HANDLE);
#else
	ret = validate_handle( sessions, session, SESSION);
#endif //STATIC_MEM

	if (ret==DCAL_SUCCESS) {
		//TODO: do something interesting with keydata
	}

	return REPORT_RETURN_DBG(ret);
}

DCAL_ERR dcal_session_open ( laird_session_handle session )
{
	DCAL_ERR ret = DCAL_NOT_IMPLEMENTED;

	REPORT_ENTRY_DEBUG;
	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;

	return REPORT_RETURN_DBG(ret);
}

DCAL_ERR dcal_session_close( laird_session_handle session)
{
	DCAL_ERR ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else {
#ifdef STATIC_MEM

		((internal_session_handle)session)->valid = 0;

#else

		ret = remove_from_list(&sessions, session);
		if (ret==DCAL_SUCCESS){
			free(session);
			session = NULL;
		}

#endif
	}

	return REPORT_RETURN_DBG(ret);
}


