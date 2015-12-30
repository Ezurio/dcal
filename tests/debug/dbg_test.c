#include <stdio.h>
#include "lrd_remote_api.h"
#define DEBUG 1
#include "../../src/include/debug.h"  // customers should not do this

extern int debug_to_stdout;
extern int debug_level;
const char *LRD_API_ERR_to_string( LRD_API_ERR code);

int main ()
{
	REPORT_ENTRY_DEBUG;

	printf("debug is %s\n", debug_to_stdout==0?"inactive":debug_to_stdout==2?"time stamped":"active");

	if (debug_to_stdout)
		printf("debug level set to %d\n", debug_level);

	return REPORT_RETURN_DBG(0);
}
