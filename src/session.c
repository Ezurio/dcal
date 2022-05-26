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

	if (ssh_init())
		DBGERROR("ssh_init() failed\n");
}

void __attribute__ ((destructor)) sessions_fini(void)
{
	int rc;
	rc = freelist(&sessions);
	sessions = NULL;
	if(rc)
		DBGERROR("freelist() failed for sessions list with: %d\n", rc);
	if (ssh_finalize())
		DBGERROR("ssh_finalize() failed\n");
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
	enum ssh_known_hosts_e state;
	char buf[10];
	unsigned char *hash = NULL;
	size_t hlen;
	ssh_key srv_pubkey;
	int rc;

	state = ssh_session_is_known_server(session);

	rc = ssh_get_server_publickey(session, &srv_pubkey);
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
	case SSH_KNOWN_HOSTS_OK:
		break; /* ok */
	case SSH_KNOWN_HOSTS_CHANGED:
		DBGERROR("Host key for server changed : server's one is now :\n");
		ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
		ssh_clean_pubkey_hash(&hash);
		DBGERROR("For security reason, connection will be stopped\n");
		return REPORT_RETURN_DBG(-1);
	case SSH_KNOWN_HOSTS_OTHER:
		DBGERROR("The host key for this server was not found but an other type of key exists.\n");
		DBGERROR("An attacker might change the default server key to confuse your client"
		        "into thinking the key does not exist\n"
		        "We advise you to rerun the client with -d or -r for more safety.\n");
		return REPORT_RETURN_DBG(-1);
	case SSH_KNOWN_HOSTS_NOT_FOUND:
		DBGERROR("Could not find known host file. If you accept the host key here,\n"
			"the file will be automatically created.\n");
		/* fallback to SSH_SERVER_NOT_KNOWN behavior */
	case SSH_KNOWN_HOSTS_UNKNOWN:
		hexa = ssh_get_hexa(hash, hlen);
		printf("The server is unknown. \nPublic key hash: %s\n"
		"Do you trust the host key ?\n", hexa);
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
			if (ssh_session_update_known_hosts(session) != SSH_OK) {
				ssh_clean_pubkey_hash(&hash);
				fprintf(stderr, "error %s\n", strerror(errno));
				return REPORT_RETURN_DBG(-1);
			}
		}

		break;
	case SSH_KNOWN_HOSTS_ERROR:
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
		INIT_LOCK((*session)->chan_lock);
		INIT_LOCK((*session)->list_lock);
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

int dcal_set_keyfile( laird_session_handle s, char *fn )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;
	if ((session==NULL) || (fn==NULL) || !strlen(fn))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;
	else
		strncpy(session->keyfile, fn, FILENAME_SZ);

	return REPORT_RETURN_DBG(ret);
}


static int auth_auto(internal_session_handle session)
{
	return ssh_userauth_publickey_auto(session->ssh, NULL, NULL);
}

static int auth_keyfile(internal_session_handle session)
{
	ssh_key key = NULL;
	char pubkey[FILENAME_SZ+4]; // +".pub"
	int rc;

	snprintf(pubkey, FILENAME_SZ+4, "%s.pub", session->keyfile);

	rc = ssh_pki_import_pubkey_file( pubkey, &key);

	if (rc != SSH_OK)
		return SSH_AUTH_DENIED;

	rc = ssh_userauth_try_publickey(session->ssh, NULL, key);

	ssh_key_free(key);

	if (rc!=SSH_AUTH_SUCCESS)
		return SSH_AUTH_DENIED;

	rc = ssh_pki_import_privkey_file(session->keyfile, NULL, NULL, NULL, &key);

	if (rc != SSH_OK)
		return SSH_AUTH_DENIED;

	rc = ssh_userauth_publickey(session->ssh, NULL, key);

	ssh_key_free(key);

	return rc;

}

static int auth_password(internal_session_handle session)
{
	return ssh_userauth_password(session->ssh, NULL, session->pw);
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
		if (session->user[0])
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

		rc = auth_auto(session);

		if(rc==SSH_AUTH_SUCCESS)
			DBGINFO("Authenticated with auth_auto\n");
		else if( session->keyfile[0]){
			rc = auth_keyfile(session);
			if(rc==SSH_AUTH_SUCCESS)
				DBGINFO("Authenticated with auth_keyfile\n");
		}

		if((rc != SSH_AUTH_SUCCESS) && session->pw[0]){
			rc = auth_password(session);
			if(rc==SSH_AUTH_SUCCESS)
				DBGINFO("Authenticated with auth_password\n");
		}

		if(rc != SSH_AUTH_SUCCESS) {
			DBGINFO("Error authenticating\n");
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

		DESTROY_LOCK(session->chan_lock);
		DESTROY_LOCK(session->list_lock);
		if (session->scan_items)
			free(session->scan_items);
		if (session->profiles)
			free(session->profiles);
		if (session->status.ipv6_strs)
			free(session->status.ipv6_strs);
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
	size_t nwrite = 0;
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

int lock_session_channel(laird_session_handle s)
{
	if(!validate_session(s))
		return DCAL_INVALID_HANDLE;

	LOCK(((internal_session_handle)s)->chan_lock);
	return DCAL_SUCCESS;
}

int unlock_session_channel(laird_session_handle s)
{
	if(!validate_session(s))
		return DCAL_INVALID_HANDLE;

	UNLOCK(((internal_session_handle)s)->chan_lock);
	return DCAL_SUCCESS;
}

// this API will use a local ssh_session rather than the one in the laird
// session handle in order to avoid having to determine and deal with the
// state of the internal ssh_session.
int dcal_get_auth_methods ( laird_session_handle s, int * method )
{
	internal_session_handle session = (internal_session_handle)s;
	int ret = -1;
	int ssh_method;

	if ((s==NULL) || (method==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(sessions, s))
		ret = DCAL_INVALID_HANDLE;

	ssh_session temp_session;
	temp_session=ssh_new();
	if (temp_session==NULL){
		DBGERROR("ssh_new() failed\n");
		ret = DCAL_NO_MEMORY;
		goto bad_session;
	}

	if (ssh_options_set(temp_session, SSH_OPTIONS_HOST, session->host) < 0){
		DBGERROR("unable to set ssh host: %s\n", session->host);
		ret = DCAL_SSH_ERROR;
		goto cleanup_session;
	}

	if (ssh_options_set(temp_session, SSH_OPTIONS_PORT, &session->port) < 0){
		DBGERROR("unable to set port: %d\n", session->port);
		ret = DCAL_SSH_ERROR;
		goto cleanup_session;
	}

	if (ssh_options_set(temp_session, SSH_OPTIONS_LOG_VERBOSITY, &session->verbosity) <0){
		DBGERROR("unable to set verbosity: %d\n", session->verbosity);
		ret = DCAL_SSH_ERROR;
		goto cleanup_session;
	}

	if (ssh_connect(temp_session)) {
		DBGERROR("unable to connect. error: %d\n", ssh_get_error(temp_session));
		ret = DCAL_SSH_ERROR;
		goto cleanup_disconnect;
	}

	ret = ssh_userauth_none(temp_session, NULL);
	if (ret == SSH_AUTH_SUCCESS || ret == SSH_AUTH_ERROR) {
		ret = DCAL_SSH_ERROR;
		goto cleanup_session;
	}

	ssh_method = ssh_userauth_list(temp_session, NULL);
	*method=0;
	if(ssh_method & SSH_AUTH_METHOD_PUBLICKEY)
		*method |= METHOD_PUBKEY;
	if(ssh_method & SSH_AUTH_METHOD_PASSWORD)
		*method |= METHOD_PASSWORD;

	ret = DCAL_SUCCESS;

cleanup_disconnect:
	ssh_disconnect(temp_session);
cleanup_session:
	ssh_free(temp_session);
bad_session:
	return ret;
}

