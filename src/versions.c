#include "session.h"
#include "debug.h"
#include "buffer.h"
#include "dcal_api.h"

#define BUF_SZ 2048

int build_query_version( flatcc_builder_t *B)
{

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_GETVERSIONS)));
	ns(Command_end_as_root(B));

	return 0;
}

int dcal_get_sdk_version(laird_session_handle session, unsigned int *sdk)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (sdk==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	*sdk = ((internal_session_handle)session)->versions.sdk;
	return DCAL_SUCCESS;
}

int dcal_get_chipset_version(laird_session_handle session,
                              RADIOCHIPSET *chipset)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (chipset==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	*chipset = ((internal_session_handle)session)->versions.chipset;
	return DCAL_SUCCESS;
}

int dcal_get_system_version(laird_session_handle session,
                              LRD_SYSTEM *sys)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (sys==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	*sys = ((internal_session_handle)session)->versions.sys;
	return DCAL_SUCCESS;
}

int dcal_get_driver_version(laird_session_handle session,
                              unsigned int *driver)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (driver==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	*driver = ((internal_session_handle)session)->versions.driver;
	return DCAL_SUCCESS;
}

int dcal_get_dcas_version(laird_session_handle session,
                              unsigned int *dcas)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (dcas==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	*dcas = ((internal_session_handle)session)->versions.dcas;
	return DCAL_SUCCESS;
}

int dcal_get_dcal_version(laird_session_handle session,
                              unsigned int *dcal)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (dcal==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	*dcal = ((internal_session_handle)session)->versions.dcal;
	return DCAL_SUCCESS;
}

int dcal_get_firmware_version(laird_session_handle session,
                              char *firmware, size_t buflen)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (firmware==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	if(buflen <
	     strlen(((internal_session_handle)session)->versions.firmware)+1)
		return DCAL_BUFFER_TOO_SMALL;

	strncpy(firmware, ((internal_session_handle)session)->versions.firmware, buflen);
	return DCAL_SUCCESS;
}

int dcal_get_supplicant_version(laird_session_handle session,
                              char *supplicant, size_t buflen)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (supplicant==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	if(buflen <
	     strlen(((internal_session_handle)session)->versions.supplicant)+1)
		return DCAL_BUFFER_TOO_SMALL;

	strncpy(supplicant, ((internal_session_handle)session)->versions.supplicant, buflen);
	return DCAL_SUCCESS;
}

int dcal_get_release_version(laird_session_handle session,
                              char *release, size_t buflen)
{
	if (!validate_session(session))
		return(DCAL_INVALID_HANDLE);
	if (release==NULL)
		return(DCAL_INVALID_PARAMETER);

	if (((internal_session_handle)session)->versions.valid==false)
		return DCAL_DATA_STALE;

	if(buflen <
	     strlen(((internal_session_handle)session)->versions.release)+1)
		return DCAL_BUFFER_TOO_SMALL;

	strncpy(release, ((internal_session_handle)session)->versions.release, buflen);
	return DCAL_SUCCESS;
}

int version_pull(internal_session_handle session)
{
	int ret = DCAL_SUCCESS;
	char buffer[BUF_SZ];
	size_t i, size = 0;
	flatcc_builder_t *B;
	ns(Version_table_t) version = NULL;
	flatbuffers_thash_t buftype;

	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);

	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);

	B = &session->builder;

	size = BUF_SZ;
	memset(buffer, 0, BUF_SZ);
	build_query_version(B);

	size = flatcc_builder_get_buffer_size(B);
	assert(size <= BUF_SZ);
	flatcc_builder_copy_buffer(B, buffer, size);

	ret = lock_session_channel(session);
	if(ret)
		return REPORT_RETURN_DBG(ret);
	ret = dcal_send_buffer( session, buffer, size);

	if (ret != DCAL_SUCCESS) {
		unlock_session_channel(session);
		return REPORT_RETURN_DBG(ret);
	}
// get response
	size = BUF_SZ;
	ret = dcal_read_buffer( session, buffer, &size);
	unlock_session_channel(session);

	if (ret != DCAL_SUCCESS)
		return REPORT_RETURN_DBG(ret);

//is return buffer a version buffer?
	buftype = verify_buffer(buffer, size);

	if(buftype != ns(Version_type_hash)){
		if(buftype != ns(Handshake_type_hash)){
			DBGERROR("could not verify version buffer.  Validated as: %s\n", buftype_to_string(buftype));
			return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
		}
		ret = handshake_error_code(ns(Handshake_as_root(buffer)));

		DBGERROR("Expecting Version table.  Received handshake with: %s\n" ,
		          dcal_err_to_string(ret));
		return REPORT_RETURN_DBG (ret);
	}

	version = ns(Version_as_root(buffer));

	session->versions.sdk = ns(Version_sdk(version));
	session->versions.chipset = ns(Version_chipset(version));
	session->versions.sys = ns(Version_sys(version));
	session->versions.driver = ns(Version_driver(version));
	session->versions.dcas = ns(Version_dcas(version));
	session->versions.dcal = DCAL_VERSION;
	strncpy(session->versions.firmware, ns(Version_firmware(version)), STR_SZ);
	strncpy(session->versions.supplicant, ns(Version_supplicant(version)), STR_SZ);
	strncpy(session->versions.release, ns(Version_release(version)), STR_SZ);
	session->versions.valid = true;

	return REPORT_RETURN_DBG (ret);
}

