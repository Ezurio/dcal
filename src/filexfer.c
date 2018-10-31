#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include "dcal_api.h"
#include "dcal_internal_api.h"
#include "debug.h"
#include "session.h"
#include "buffer.h"

#define BUFSIZE 1024

// local_file is the full path and file name on host. remote_file can be
// NULL in which case the basename of local_file will be used. The
// remote_file will be saved to /tmp/ on WB.  NOTE: /tmp is not persistent
// ont he WB as /tmp is a ramdisk.
int dcal_file_push_to_wb(laird_session_handle session,
                             char * local_file_name,
                             char * remote_file_name)
{
	int ret = DCAL_SUCCESS;
	FILE *file= NULL;
	int fd, r,w, total, mode;
	size_t size, filesize;
	struct stat stats;
	internal_session_handle s = (internal_session_handle)session;
	char *buf;
	REPORT_ENTRY_DEBUG;

	if (local_file_name==NULL)
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);
	
	if (remote_file_name==NULL)
		remote_file_name = local_file_name;

	if (!validate_session(session))
		return REPORT_RETURN_DBG(DCAL_INVALID_HANDLE);

	buf = malloc(FILEBUFSZ);
	if (!buf)
		return REPORT_RETURN_DBG(DCAL_NO_MEMORY);
	memset(buf, 0, FILEBUFSZ);

	file = fopen(local_file_name, "r");
	if (!file)
		return REPORT_RETURN_DBG(DCAL_LOCAL_FILE_ACCESS_DENIED);

	fd=fileno(file);
	if(fd < 0) {
		ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
		goto closefile;
	}

	size = fstat(fd, &stats);
	if (size < 0) {
		ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
		goto closefile;
	}

	filesize = stats.st_size;
	mode = stats.st_mode & ~S_IFMT;//TODO - do we need to check for directory instead of file?

	flatcc_builder_t *B;
	B=&s->builder;
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_FILEPUSH)));

	ns(Command_cmd_pl_Filexfer_start(B));
	ns(Filexfer_file_path_create_str(B, remote_file_name));
	ns(Filexfer_size_add(B, filesize));
	ns(Filexfer_mode_add(B, mode));
	ns(Command_cmd_pl_Filexfer_end(B));

	ns(Command_end_as_root(B));

	size=flatcc_builder_get_buffer_size(B);
	assert(size<=FILEBUFSZ);
	flatcc_builder_copy_buffer(B, buf, size);

	ret = lock_session_channel(session);
	if(ret)
		goto closefile;

	ret=dcal_send_buffer(session, buf, size);

	if (ret!=DCAL_SUCCESS) {
		unlock_session_channel(session);
		goto closefile;
	}

	size = FILEBUFSZ;
	ret = dcal_read_buffer(session, buf, &size);

	if(ret != DCAL_SUCCESS) {
		unlock_session_channel(session);
		goto closefile;
	}

	flatbuffers_thash_t buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		unlock_session_channel(session);
		goto closefile;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));

	if (ret != DCAL_SUCCESS){
		unlock_session_channel(session);
		goto closefile;
	}

	total = 0;
	do {
		r = fread(buf, 1, FILEBUFSZ, file);
		if (r==0) break;
		else if (r<0){
			DBGERROR("Error reading file: %s\n", strerror(errno));
			ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
			unlock_session_channel(session);
			goto closefile;
		}
		DBGINFO("Read %d bytes\n", r);

		ret=dcal_send_buffer(session, buf, r);
		if(ret!=DCAL_SUCCESS){
			DBGERROR("Error writing to socket: %s\n", dcal_err_to_string(ret));
			unlock_session_channel(session);
			goto closefile;
		}
		DBGINFO("Wrote %d bytes\n", r);

		total+=r;
	}while (total < filesize);

	DBGINFO("Wrote %d bytes total\n", total);

	size = FILEBUFSZ;
	ret = dcal_read_buffer(session, buf, &size);

	unlock_session_channel(session);

	if(ret != DCAL_SUCCESS) {
		goto closefile;
	}

	buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		goto closefile;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));

	closefile:
	fclose(file);
	safe_free(buf);

	return REPORT_RETURN_DBG(ret);
}

// remote_file_name is full path and filename on WB.  local_file_name is
// the full path and file name on host. local_file_name can be NULL in
// which case remote_file_name base name will be used in the local directory
int dcal_file_pull_from_wb(laird_session_handle session,
                             char * remote_file, char * local_file)
{
	char *buf = NULL;
	char *tmp = NULL;
	char *local_file_name = NULL;
	int ret = DCAL_SUCCESS;
	FILE *file = NULL;
	int fd, total, w, remaining;
	mode_t mode;
	size_t r, size;
	internal_session_handle s = (internal_session_handle)session;

	REPORT_ENTRY_DEBUG;

	if (!validate_session(session))
		return REPORT_RETURN_DBG(DCAL_INVALID_HANDLE);

	if (remote_file==NULL)
		return DCAL_INVALID_PARAMETER;

	if (local_file==NULL){
		tmp = strdup(remote_file);
		local_file_name = strdup(basename(tmp));
	}else
		local_file_name = strdup(local_file);

	buf = malloc(FILEBUFSZ);
	if (!buf)
		return REPORT_RETURN_DBG(DCAL_NO_MEMORY);
	memset(buf, 0, FILEBUFSZ);

	file = fopen(local_file_name, "wb");
	if (!file){
		DBGERROR("unable to open local file: %s for writing\n", local_file_name);
		ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
		goto cleanup;
	}

	flatcc_builder_t *B;
	B=&s->builder;
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_FILEPULL)));

	ns(Command_cmd_pl_Filexfer_start(B));
	ns(String_value_create_str(B, remote_file));
	ns(Command_cmd_pl_Filexfer_end(B));

	ns(Command_end_as_root(B));

	size=flatcc_builder_get_buffer_size(B);
	assert(size<=FILEBUFSZ);
	flatcc_builder_copy_buffer(B, buf, size);

	ret = lock_session_channel(session);
	if(ret)
		goto cleanup;

	ret=dcal_send_buffer(session, buf, size);

	if (ret!=DCAL_SUCCESS) {
		goto unlock_chan;
	}

	size = FILEBUFSZ;
	ret = dcal_read_buffer(session, buf, &size);

	if(ret != DCAL_SUCCESS) {
		goto unlock_chan;
	}

	flatbuffers_thash_t buftype = verify_buffer(buf, size);

	if(buftype == ns(Handshake_type_hash)){
		ret = handshake_error_code(ns(Handshake_as_root(buf)));
		if (ret == DCAL_SUCCESS) {
			DBGERROR("expecting a FileXfer buffer but received an ACK\n");
			ret = DCAL_FLATBUFF_ERROR;
		}
		goto unlock_chan;
	} else if(buftype != ns(Command_type_hash)){
		DBGERROR("could not verify incoming Filexfer buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		goto unlock_chan;
	}

	ns(Filexfer_table_t) fxt;
	ns(Command_table_t) cmd;
	cmd = ns(Command_as_root(buf));
	fxt = ns(Command_cmd_pl(cmd));
	// we don't care what file name was sent as the user specified in the call to this function
	mode = ns(Filexfer_mode(fxt));
	size = ns(Filexfer_size(fxt));
	total = 0;

	remaining = size;
	do {
		r = FILEBUFSZ;
		if (r > remaining)
			r=remaining;
		ret = dcal_read_buffer(session, buf, &r);
		if (ret==SSH_ERROR) {
			DBGERROR("Failure to read ssh buffer\n");
			ret = DCAL_SSH_ERROR;
			break;
		} else if (r==0)
			break;
		w = fwrite(buf, r, 1, file);
		if (w<0) {
			DBGERROR("Error writing to local file: %s\n", local_file_name);
			ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
			break;
		}
		remaining -=r;
		total += r;
		sleep(1);
	} while (remaining > 0);

	if (ret==DCAL_SUCCESS){
		DBGINFO("read %d bytes from socket written to %s\n", total, local_file_name);
		if (chmod(local_file_name, mode))
			ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
		}

	unlock_chan:
	unlock_session_channel(session);

	cleanup:
	if (file)
		fclose(file);
	safe_free(buf);
	safe_free(tmp);
	safe_free(local_file_name);
	return ret;
}

// in order to issue the fw_update() function, the desired files must first
// be transfered to the remote device.  This includes the fw.txt file.  The
// files will be placed in the /tmp directory on the WB.  When this function
// is executed, firmware update will be attempted on the transfered fw.txt
// file in /tmp.  fw_update flags can be set in the flags variable.  Flags
// can also be set in the fw.txt file itself.
// NOTE: The disable reboot flag will be added by dcas so the user must
// specifically call dcal_system_restart() when desiring restart after
// fw_update.
int dcal_fw_update(laird_session_handle session, int flags)
{
	char buf[BUFSIZE];
	size_t size=BUFSIZE;
	int ret = DCAL_SUCCESS;
	internal_session_handle s = (internal_session_handle)session;

	flatcc_builder_t *B;
	B=&s->builder;
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_FWUPDATE)));

	ns(Command_cmd_pl_Filexfer_start(B));
	ns(U32_value_add(B, flags));
	ns(Command_cmd_pl_Filexfer_end(B));

	ns(Command_end_as_root(B));

	size=flatcc_builder_get_buffer_size(B);
	assert(size<=BUFSIZE);
	flatcc_builder_copy_buffer(B, buf, size);

	ret = lock_session_channel(session);
	if(ret)
		return ret;

	ret=dcal_send_buffer(session, buf, size);

	if (ret!=DCAL_SUCCESS) {
		unlock_session_channel(session);
		return ret;
	}

	size = BUFSIZE;
	ret = dcal_read_buffer(session, buf, &size);

	if(ret != DCAL_SUCCESS) {
		unlock_session_channel(session);
		return ret;
	}

	flatbuffers_thash_t buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		unlock_session_channel(session);
		return ret;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));
	unlock_session_channel(session);

	return ret;
}

// dest_file is full location and file name where log should be saved
int dcal_pull_logs(laird_session_handle session, char * dest_file)
{
	char buf[BUFSIZE];
	size_t size=BUFSIZE;
	int ret = DCAL_SUCCESS;
	internal_session_handle s = (internal_session_handle)session;

	if (dest_file==NULL)
		return DCAL_INVALID_PARAMETER;

	flatcc_builder_t *B;
	B=&s->builder;
	flatcc_builder_reset(B);

	flatbuffers_buffer_start(B, ns(Command_type_identifier));
	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_GETLOGS)));
	ns(Command_end_as_root(B));

	size=flatcc_builder_get_buffer_size(B);
	assert(size<=BUFSIZE);
	flatcc_builder_copy_buffer(B, buf, size);

	ret = lock_session_channel(session);
	if(ret)
		return ret;

	ret=dcal_send_buffer(session, buf, size);

	if (ret!=DCAL_SUCCESS) {
		unlock_session_channel(session);
		return ret;
	}

	size = BUFSIZE;
	ret = dcal_read_buffer(session, buf, &size);
	unlock_session_channel(session);

	if(ret != DCAL_SUCCESS) {
		return ret;
	}

	flatbuffers_thash_t buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		unlock_session_channel(session);
		return ret;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));
	unlock_session_channel(session);

	if (ret==DCAL_SUCCESS)
		ret = dcal_file_pull_from_wb(session,  "/tmp/log_dump.txt", dest_file);

	return ret;
}

// src_file is full location and file name where command file resides.
int dcal_process_cli_command_file(laird_session_handle session, char * src_file)
{
	char buf[BUFSIZE];
	size_t size=BUFSIZE;
	int ret = DCAL_SUCCESS;
	internal_session_handle s = (internal_session_handle)session;

	if (src_file==NULL)
		return DCAL_INVALID_PARAMETER;

	ret = dcal_file_push_to_wb(session, src_file, src_file);

	flatcc_builder_t *B;
	B=&s->builder;
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_CLIFILE)));

	ns(Command_cmd_pl_Filexfer_start(B));
	ns(String_value_create_str(B, src_file));
	ns(Command_cmd_pl_Filexfer_end(B));

	ns(Command_end_as_root(B));

	size=flatcc_builder_get_buffer_size(B);
	assert(size<=BUFSIZE);
	flatcc_builder_copy_buffer(B, buf, size);

	ret = lock_session_channel(session);
	if(ret)
		return ret;

	ret=dcal_send_buffer(session, buf, size);

	if (ret!=DCAL_SUCCESS) {
		unlock_session_channel(session);
		return ret;
	}

	size = BUFSIZE;
	ret = dcal_read_buffer(session, buf, &size);

	if(ret != DCAL_SUCCESS) {
		unlock_session_channel(session);
		return ret;
	}

	flatbuffers_thash_t buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		unlock_session_channel(session);
		return ret;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));
	unlock_session_channel(session);

	return ret;
}

int dcal_cert_push_to_wb(laird_session_handle session,
                             char * local_cert_name)
{
	int ret = DCAL_SUCCESS;
	FILE *file= NULL;
	int fd, r,w, total, mode;
	size_t size, filesize;
	struct stat stats;
	internal_session_handle s = (internal_session_handle)session;
	char *buf;
	REPORT_ENTRY_DEBUG;

	if (local_cert_name==NULL)
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);

	if (!validate_session(session))
		return REPORT_RETURN_DBG(DCAL_INVALID_HANDLE);

	buf = malloc(FILEBUFSZ);
	if (!buf)
		return REPORT_RETURN_DBG(DCAL_NO_MEMORY);
	memset(buf, 0, FILEBUFSZ);

	//TODO add cert file verification
	file = fopen(local_cert_name, "r");
	if (!file)
		return REPORT_RETURN_DBG(DCAL_LOCAL_FILE_ACCESS_DENIED);

	fd=fileno(file);
	if(fd < 0) {
		ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
		goto closefile;
	}

	size = fstat(fd, &stats);
	if (size < 0) {
		ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
		goto closefile;
	}

	filesize = stats.st_size;
	mode = stats.st_mode & ~S_IFMT;//TODO - do we need to check for directory instead of file?

	flatcc_builder_t *B;
	B=&s->builder;
	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_FILEPUSH)));

	ns(Command_cmd_pl_Filexfer_start(B));
	ns(Filexfer_file_path_create_str(B, local_cert_name));
	ns(Filexfer_size_add(B, filesize));
	ns(Filexfer_mode_add(B, mode));
	ns(Filexfer_cert_add(B, 1));
	ns(Command_cmd_pl_Filexfer_end(B));

	ns(Command_end_as_root(B));

	size=flatcc_builder_get_buffer_size(B);
	assert(size<=FILEBUFSZ);
	flatcc_builder_copy_buffer(B, buf, size);

	ret = lock_session_channel(session);
	if(ret)
		goto closefile;

	ret=dcal_send_buffer(session, buf, size);

	if (ret!=DCAL_SUCCESS) {
		unlock_session_channel(session);
		goto closefile;
	}

	size = FILEBUFSZ;
	ret = dcal_read_buffer(session, buf, &size);

	if(ret != DCAL_SUCCESS) {
		unlock_session_channel(session);
		goto closefile;
	}

	flatbuffers_thash_t buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		unlock_session_channel(session);
		goto closefile;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));

	if (ret != DCAL_SUCCESS){
		unlock_session_channel(session);
		goto closefile;
	}

	total = 0;
	do {
		r = fread(buf, 1, FILEBUFSZ, file);
		if (r==0) break;
		else if (r<0){
			DBGERROR("Error reading file: %s\n", strerror(errno));
			ret = DCAL_LOCAL_FILE_ACCESS_DENIED;
			unlock_session_channel(session);
			goto closefile;
		}
		DBGINFO("Read %d bytes\n", r);

		ret=dcal_send_buffer(session, buf, r);
		if(ret!=DCAL_SUCCESS){
			DBGERROR("Error writing to socket: %s\n", dcal_err_to_string(ret));
			unlock_session_channel(session);
			goto closefile;
		}
		DBGINFO("Wrote %d bytes\n", r);

		total+=r;
	}while (total < filesize);

	DBGINFO("Wrote %d bytes total\n", total);

	size = FILEBUFSZ;
	ret = dcal_read_buffer(session, buf, &size);

	unlock_session_channel(session);

	if(ret != DCAL_SUCCESS) {
		goto closefile;
	}

	buftype = verify_buffer(buf, size);
	if(buftype != ns(Handshake_type_hash)){
		DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
		ret = DCAL_FLATBUFF_ERROR;
		goto closefile;
	}
	ret = handshake_error_code(ns(Handshake_as_root(buf)));

	closefile:
	fclose(file);
	safe_free(buf);

	return REPORT_RETURN_DBG(ret);
}
