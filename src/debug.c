#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include "debug.h"
#include "sdc_sdk_legacy.h"

#include "dcal_internal_api.h"

int debug_to_stdout=0;
int debug_level=0;

#ifdef DEBUG
// there are two options for debug.  If the environment is set, debugging is
// enabled and will be output to stdout.  If the value it is set is 'time'
// time stamps will be included

#define LAIRD_ENV "DCAL_DEBUG"
#define LAIRD_ENV_LVL "DCAL_DEBUG_LEVEL"

static struct timeval basetime = {0,0};

// from http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
int timeval_subtract (result, x, y)
struct timeval *result, *x, *y;
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

const char *dcal_dbg_lvl_to_string( int code)
{
	switch(code) {
		case DCAL_DBG_NONE: return "None";
		case DCAL_DBG_ERROR: return "Error";
		case DCAL_DBG_WARNING: return "Warning";
		case DCAL_DBG_INFO: return "Info";
		case DCAL_DBG_DEBUG: return "Debug";
		case DCAL_DBG_MSGDUMP: return "MSGDUMP";
		case DCAL_DBG_EXCESSIVE: return "Excessive";
		default: return "unknown";
	}
}

void __attribute__ ((constructor)) debuginit(void)
{
	struct timeval tv;
	char *env = getenv(LAIRD_ENV);
	char *envl = getenv(LAIRD_ENV_LVL);
	int lvl = 0;

	gettimeofday(&tv, NULL);
	if (!basetime.tv_sec) {
		basetime.tv_sec = tv.tv_sec;
		basetime.tv_usec = tv.tv_usec;
	}

	if (env==NULL)
		return;  // not set so keep it turned off

	debug_to_stdout=1;  // one is std_out; two means timestamps are on

	if (strstr(env, "time"))
		debug_to_stdout=2;

	debug_level = DCAL_DBG_ERROR; // default to minimum
	if (envl) {
		lvl=(int)strtol(envl, NULL, 10);
		if (lvl >= DCAL_DBG_NONE)
			debug_level = lvl;
	}
	printf("Debug error level set to: %s (%d)\n",dcal_dbg_lvl_to_string(debug_level), debug_level);
}

void DbgPrintfLvl(int dbglvl, char *format, ...)
{
	va_list args;
	struct timeval tv;
	FILE *fp = stdout;

	if (dbglvl > debug_level)
		return;

	if(debug_to_stdout==2){
		gettimeofday(&tv, NULL);
		timeval_subtract(&tv, &tv, &basetime);
		fprintf( fp, "%4ld.%06ld ", tv.tv_sec, tv.tv_usec);
	}

	va_start( args, format );
	vfprintf( fp, format, args );
	va_end( args );
}

#endif //DEBUG
#define BUFSIZE 1024
char debugbuf[BUFSIZE] = {0};
const char *dcal_err_to_string( int code)
{
	switch(code)
	{
		case DCAL_SUCCESS:                 return "DCAL_SUCCESS";
		case DCAL_WB_GENERAL_FAIL:         return "DCAL_WB_GENERAL_FAIL";
		case DCAL_WB_INVALID_NAME:         return "DCAL_WB_INVALID_NAME";
		case DCAL_WB_INVALID_CONFIG:       return "DCAL_WB_INVALID_CONFIG";
		case DCAL_WB_INVALID_DELETE:       return "DCAL_WB_INVALID_DELETE";
		case DCAL_WB_POWERCYCLE_REQUIRED:  return "DCAL_WB_POWERCYCLE_REQUIRED";
		case DCAL_WB_INVALID_PARAMETER:    return "DCAL_WB_INVALID_PARAMETER";
		case DCAL_WB_INVALID_EAP_TYPE:     return "DCAL_WB_INVALID_EAP_TYPE";
		case DCAL_WB_INVALID_WEP_TYPE:     return "DCAL_WB_INVALID_WEP_TYPE";
		case DCAL_WB_INVALID_FILE:         return "DCAL_WB_INVALID_FILE";
		case DCAL_WB_INSUFFICIENT_MEMORY:  return "DCAL_WB_INSUFFICIENT_MEMORY";
		case DCAL_WB_NOT_IMPLEMENTED:      return "DCAL_WB_NOT_IMPLEMENTED";
		case DCAL_WB_NO_HARDWARE:          return "DCAL_WB_NO_HARDWARE";
		case DCAL_WB_INVALID_VALUE:        return "DCAL_WB_INVALID_VALUE";

		case DCAL_INVALID_PARAMETER:       return "DCAL_INVALID_PARAMETER";
		case DCAL_INVALID_HANDLE:          return "DCAL_INVALID_HANDLE";
		case DCAL_HANDLE_IN_USE:           return "DCAL_HANDLE_IN_USE";
		case DCAL_HANDLE_NOT_ACTIVE:       return "DCAL_HANDLE_NOT_ACTIVE";
		case DCAL_NO_NETWORK_ACCESS:       return "DCAL_NO_NETWORK_ACCESS";
		case DCAL_NO_MEMORY:               return "DCAL_NO_MEMORY";
		case DCAL_NOT_IMPLEMENTED:         return "DCAL_NOT_IMPLEMENTED";
		case DCAL_INVALID_CONFIGURATION:   return "DCAL_INVALID_CONFIGURATION";
		case DCAL_SSH_ERROR:               return "DCAL_SSH_ERROR";
		case DCAL_FLATBUFF_ERROR:          return "DCAL_FLATBUFF_ERROR";
		case DCAL_FLATCC_NOT_INITIALIZED:  return "DCAL_FLATCC_NOT_INITIALIZED";
		case DCAL_FLATBUFF_VALIDATION_FAIL:return "DCAL_FLATBUFF_VALIDATION_FAIL";
		case DCAL_DATA_STALE:              return "DCAL_DATA_STALE";
		case DCAL_LOCAL_FILE_ACCESS_DENIED:return "DCAL_LOCAL_FILE_ACCESS_DENIED";
		case DCAL_REMOTE_FILE_ACCESS_DENIED:return "DCAL_REMOTE_FILE_ACCESS_DENIED";
		case DCAL_FQDN_FAILURE:             return "DCAL_FQDN_FAILURE";
		case DCAL_REMOTE_SHELL_CMD_FAILURE: return "DCAL_REMOTE_SHELL_CMD_FAILURE";
		case DCAL_REMOTE_USER_CMD_NOT_EXIST: return "DCAL_REMOTE_USER_CMD_NOT_EXIST";

		default:                     snprintf(debugbuf, BUFSIZE, "unknown DCAL_ERR:%d",code);
		return debugbuf;
	}
}

