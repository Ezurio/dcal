#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_api.h"
#include "dcal_internal_api.h"
#include "session.h"
#include "buffer.h"
#include "common.h"

int dcal_time_get( laird_session_handle session,
                      time_t *tv_sec, suseconds_t *tv_usec)
{
	int ret = DCAL_SUCCESS;
	REPORT_ENTRY_DEBUG;

	if ((session==NULL) || (tv_sec==NULL) || (tv_usec==NULL))
		ret = DCAL_INVALID_PARAMETER;
	#ifdef DEBUG
	else if (!validate_session(session))
		ret = DCAL_INVALID_HANDLE;
	#endif
	else {
		internal_session_handle s = (internal_session_handle)session;
		// Attempt to retrieve time from device
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Command_type_identifier));

		ns(Command_start(B));
		ns(Command_command_add(B, ns(Commands_GETTIME)));
		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);
		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS) {
			unlock_session_channel(session);
			return REPORT_RETURN_DBG(ret);
		}

		//get response
		size=BUF_SZ;
		ret = dcal_read_buffer(session, buffer, &size);
		unlock_session_channel(session);

		if (ret != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		//is return buffer an ack buffer?
		buftype = verify_buffer(buffer, size);

		if(buftype != ns(Time_type_hash)) {
			if(buftype != ns(Handshake_type_hash)){
				DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
				return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
			}

			ret =handshake_error_code(ns(Handshake_as_root(buffer)));

			DBGERROR("Failed to retrieve time.  Error received: %d\n",ret);
			return REPORT_RETURN_DBG(ret);
		}

		ns(Time_table_t) tt = ns(Time_as_root(buffer));

		*tv_sec = ns(Time_tv_sec(tt));
		*tv_usec = ns(Time_tv_usec(tt));

	}
	return REPORT_RETURN_DBG(ret);
}

int dcal_time_set( laird_session_handle session,
                      time_t tv_sec, suseconds_t tv_usec)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle s = (internal_session_handle)session;
	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_session(session))
		ret = DCAL_INVALID_HANDLE;
	else {
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Command_type_identifier));

		ns(Command_start(B));
		ns(Command_command_add(B, ns(Commands_SETTIME)));

		ns(Command_cmd_pl_Time_start(B));
		ns(Time_tv_sec_add(B, tv_sec));
		ns(Time_tv_usec_add(B, tv_usec));
		ns(Command_cmd_pl_Time_end(B));

		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);
		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS) {
			unlock_session_channel(session);
			return REPORT_RETURN_DBG(ret);
		}

		//get response
		size=BUF_SZ;
		ret = dcal_read_buffer(session, buffer, &size);
		unlock_session_channel(session);

		if (ret != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		//is return buffer an ack buffer?
			buftype = verify_buffer(buffer, size);

		if(buftype != ns(Handshake_type_hash)){
			DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
			return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
		}

		ret = handshake_error_code(ns(Handshake_as_root(buffer)));

	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_ntpdate( laird_session_handle session,
                      char * server_name )
{
	int ret = DCAL_SUCCESS;
	internal_session_handle s = (internal_session_handle)session;
	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_session(session))
		ret = DCAL_INVALID_HANDLE;
	else if(validate_fqdn(server_name)==1)
		ret = DCAL_FQDN_FAILURE;
	else {
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));

		ns(Command_start(B));
		ns(Command_command_add(B, ns(Commands_NTPDATE)));

		ns(Command_cmd_pl_Time_start(B));
		ns(String_value_create_str(B,server_name));
		ns(Command_cmd_pl_Time_end(B));

		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);
		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS) {
			unlock_session_channel(session);
			return REPORT_RETURN_DBG(ret);
		}

		//get response
		size=BUF_SZ;
		ret = dcal_read_buffer(session, buffer, &size);
		unlock_session_channel(session);

		if (ret != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		//is return buffer an ack buffer?
			buftype = verify_buffer(buffer, size);

		if(buftype != ns(Handshake_type_hash)){
			DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
			return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
		}

		ret = handshake_error_code(ns(Handshake_as_root(buffer)));

	}

	return REPORT_RETURN_DBG(ret);
}
