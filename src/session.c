#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_internal_api.h"
#include "session.h"
#include "handshake.h"
#include <errno.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#ifdef STATIC_MEM

static internal_session_struct static_session = { 0 };

#else

#include "lists.h"
static pointer_list * sessions = NULL;

#endif

void __attribute__ ((constructor)) initsessions(void)
{
	int rc;
	rc = initlist(&sessions);
	if (rc)
		DBGERROR("initlist() failed for sessions list with:%d\n", rc);
}

void __attribute__ ((destructor)) sessions_fini(void)
{
	int rc;
	rc = freelist(&sessions);
	sessions = NULL;
	if(rc)
		DBGERROR("freelist() failed for sessions list with: %d\n", rc);
}

static int get_session_handle( laird_session_handle * session )
{
	internal_session_handle handle=NULL;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

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

	return REPORT_RETURN_DBG(ret);
}

static int verify_knownhost(ssh_session session)
{
	REPORT_ENTRY_DEBUG;

	char *hexa;
	int state;
	char buf[10];
	unsigned char *hash = NULL;
	size_t hlen;
	ssh_key srv_pubkey;
	int rc;

	state=ssh_is_server_known(session);

	rc = ssh_get_publickey(session, &srv_pubkey);
	if (rc < 0) {
		return REPORT_RETURN_DBG(-1);
	}

	rc = ssh_get_publickey_hash(srv_pubkey,
	                            SSH_PUBLICKEY_HASH_SHA1,
	                            &hash,
	                            &hlen);
	ssh_key_free(srv_pubkey);
	if (rc < 0) {
		return REPORT_RETURN_DBG(-1);
	}

	switch(state) {
	case SSH_SERVER_KNOWN_OK:
		break; /* ok */
	case SSH_SERVER_KNOWN_CHANGED:
		DBGERROR("Host key for server changed : server's one is now :\n");
		ssh_print_hexa("Public key hash",hash, hlen);
		ssh_clean_pubkey_hash(&hash);
		DBGERROR("For security reason, connection will be stopped\n");
		return REPORT_RETURN_DBG(-1);
	case SSH_SERVER_FOUND_OTHER:
		DBGERROR("The host key for this server was not found but an other type of key exists.\n");
		DBGERROR("An attacker might change the default server key to confuse your client"
		        "into thinking the key does not exist\n"
		        "We advise you to rerun the client with -d or -r for more safety.\n");
		return REPORT_RETURN_DBG(-1);
	case SSH_SERVER_FILE_NOT_FOUND:
		DBGERROR("Could not find known host file. If you accept the host key here,\n"
			"the file will be automatically created.\n");
		/* fallback to SSH_SERVER_NOT_KNOWN behavior */
	case SSH_SERVER_NOT_KNOWN:
		hexa = ssh_get_hexa(hash, hlen);
		printf("The server is unknown. Do you trust the host key ?\n"
			"Public key hash: %s\n", hexa);
		ssh_string_free_char(hexa);
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			ssh_clean_pubkey_hash(&hash);
			return REPORT_RETURN_DBG(-1);
		}
		if(strncasecmp(buf,"yes",3)!=0) {
			ssh_clean_pubkey_hash(&hash);
			return REPORT_RETURN_DBG(-1);
		}
		printf("This new key will be written on disk for further usage. do you agree ?\n");
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			ssh_clean_pubkey_hash(&hash);
			return REPORT_RETURN_DBG(-1);
		}
		if(strncasecmp(buf,"yes",3)==0) {
			if (ssh_write_knownhost(session) < 0) {
				ssh_clean_pubkey_hash(&hash);
				fprintf(stderr, "error %s\n", strerror(errno));
				return REPORT_RETURN_DBG(-1);
			}
		}

		break;
	case SSH_SERVER_ERROR:
		ssh_clean_pubkey_hash(&hash);
		fprintf(stderr,"%s",ssh_get_error(session));
		return REPORT_RETURN_DBG(-1);
	}
	ssh_clean_pubkey_hash(&hash);
		return REPORT_RETURN_DBG(0);
}

int dcal_session_create( laird_session_handle * s)
{
	internal_session_handle *session = (internal_session_handle*)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	#ifdef DEBUG
	else if(validate_handle(sessions, s))
		ret = DCAL_HANDLE_IN_USE;
	#endif
	else
		ret = get_session_handle( s );

	if (ret==DCAL_SUCCESS){
		(*session)->state = SESSION_ALLOCATED;
		(*session)->port = DEF_PORT;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_set_host( laird_session_handle s, FQDN address )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (address==NULL) || !strlen(address))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else
		strncpy(session->host, address, HOST_SZ);

	return REPORT_RETURN_DBG(ret);
}

int dcal_set_port( laird_session_handle s, unsigned int port )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (port==0))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else
		session->port = port;

	return REPORT_RETURN_DBG(ret);
}

int dcal_set_user( laird_session_handle s, char *user )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (user==NULL) || !strlen(user))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else
		strncpy(session->user, user, USER_SZ);

	return REPORT_RETURN_DBG(ret);
}

int dcal_set_pw( laird_session_handle s, char *pw )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (pw==NULL) || !strlen(pw))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else
		strncpy(session->pw, pw, USER_SZ);

	return REPORT_RETURN_DBG(ret);
}

int dcal_session_open ( laird_session_handle s )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;
	int rc;

	REPORT_ENTRY_DEBUG;
	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else {
		session->verbosity = SSH_LOG_NOLOG;
		session->ssh=ssh_new();
		if (session->ssh==NULL){
			DBGERROR("ssh_new() failed\n");
			goto bad_exit;
		}

		ssh_options_set(session->ssh, SSH_OPTIONS_HOST, session->host);
		if (ssh_options_set(session->ssh, SSH_OPTIONS_USER, session->user) < 0){
			DBGERROR("unable to set ssh user: %s\n", session->user);
			goto bad_exit;
		}

		if (ssh_options_set(session->ssh, SSH_OPTIONS_PORT, &session->port) < 0){
			DBGERROR("unable to set port: %d\n", session->port);
			goto bad_exit;
		}

		if (ssh_options_set(session->ssh, SSH_OPTIONS_LOG_VERBOSITY, &session->verbosity) <0){
			DBGERROR("unable to set verbosity: %d\n", session->verbosity);
			goto bad_exit;
		}

		rc = ssh_connect(session->ssh);
		if(rc != SSH_OK) {
			DBGERROR("Error connecting to %s: %s\n", session->host, ssh_get_error(session->ssh));
			goto bad_exit;
		}

		if(verify_knownhost(session->ssh)<0) {
			DBGERROR("Unable to validate host\n");
			goto bad_exit;
		}

		rc = ssh_userauth_password(session->ssh, NULL, session->pw);

		if(rc != SSH_AUTH_SUCCESS) {
			DBGERROR("Error authenticating: %s\n",ssh_get_error(session->ssh));
			goto bad_exit;
		}

		session->channel = ssh_channel_new(session->ssh);
		if (session->channel == NULL) {
			DBGERROR("Error getting ssh channel\n");
			goto bad_exit;
		}

		rc = ssh_channel_open_session(session->channel);
		if(rc!=SSH_OK) {
			ssh_channel_free(session->channel);
			session->channel=NULL;
			DBGERROR("Error opening SSH channel\n");
			goto bad_exit;
		}

		DBGINFO("ssh connection established to host: %s\n", session->host);

		//this will initialize the builder element of the session struct
		rc = handshake_init( session );

		if (rc) {
			flatcc_builder_clear(&session->builder);
			DBGERROR("Error in handshake_init\n");
			goto bad_exit;
		}

	}

	return REPORT_RETURN_DBG(ret);

	bad_exit:
	if(ret==DCAL_SUCCESS)
		ret = DCAL_SSH_ERROR;

	return REPORT_RETURN_DBG(ret);
}

int dcal_session_close( laird_session_handle s)
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (session->builder_init){
			flatcc_builder_clear(&session->builder);
			session->builder_init = false;
		}

#ifdef STATIC_MEM

		((internal_session_handle)session)->valid = 0;

#else

		ret = remove_from_list(&sessions, session);
		if (ret==DCAL_SUCCESS){
			if(session->channel != NULL) {
				ssh_channel_send_eof(session->channel);
				ssh_channel_close(session->channel);
				ssh_channel_free(session->channel);
			}
			if(session->ssh != NULL) {
				if(ssh_is_connected(session->ssh))
					ssh_disconnect(session->ssh);
				ssh_free(session->ssh);
			}
			free(session);
			session = NULL;
		}

#endif
	}

	return REPORT_RETURN_DBG(ret);
}

// internal use only
int dcal_send_buffer(laird_session_handle s, void * buffer, size_t nbytes)
{
	internal_session_handle session = (internal_session_handle)s;
	size_t nwrite;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if ((s==NULL) || (buffer==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	if (session->channel != NULL)
		nwrite = ssh_channel_write(session->channel, buffer, nbytes);

	if (nwrite != nbytes)
		ret = DCAL_SSH_ERROR;

	return REPORT_RETURN_DBG(ret);
}

// internal use only
int dcal_read_buffer(laird_session_handle s, void * buffer, size_t *nbytes)
{
	internal_session_handle session = (internal_session_handle)s;
	int nread=0;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if ((s==NULL) || (buffer==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else {
		nread = ssh_channel_read(session->channel, buffer, *nbytes, 0);
		if (nread < 0){
			ssh_channel_close(session->channel);
			ssh_channel_free(session->channel);
			session->channel=NULL;
			DBGERROR("Error reading from SSH\n");
			ret = DCAL_SSH_ERROR;
		}
		else
			*nbytes=nread;
	}
	return REPORT_RETURN_DBG(ret);
}

int validate_session(laird_session_handle s)
{
	return validate_handle(sessions, s);
}

