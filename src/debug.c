#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include "debug.h"

#include "lrd_internal_api.h"

int debug_to_stdout=0;
int debug_level=0;

#ifdef DEBUG
// there are two options for debug.  If the environment is set, debugging is
// enabled and will be output to stdout.  If the value it is set is 'time'
// time stamps will be included

#define LAIRD_ENV "LRD_DEBUG"
#define LAIRD_ENV_LVL "LRD_DEBUG_LEVEL"

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

	debug_level = WF_DBG_ERROR; // default to minimum
	if (envl) {
		lvl=(int)strtol(envl, NULL, 10);
		if ((lvl >= WF_DBG_NONE) && (lvl <= WF_DBG_EXCESSIVE))
			debug_level = lvl;
	}
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
const char *LRD_ERR_to_string( LRD_ERR code)
{
	switch(code)
	{
		case LRD_SUCCESS:           return "LRD_SUCCESS";
		case LRD_INVALID_PARAMETER: return "LRD_INVALID_PARAMETER";
		case LRD_INVALID_HANDLE:    return "LRD_INVALID_HANDLE";
		case LRD_NO_NETWORK_ACCESS: return "LRD_NO_NETWORK_ACCESS";
		case LRD_NOT_IMPLEMENTED:   return "LRD_NOT_IMPLEMENTED";
		default:                        return "unknown LRD_ERR";
	}
}

