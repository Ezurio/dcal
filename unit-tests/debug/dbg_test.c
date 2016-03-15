#include <stdio.h>
#include <dlfcn.h>
#include "dcal_api.h"
#define DEBUG 1
#include "debug.h"

extern int debug_to_stdout;
extern int debug_level;

int main ()
{

	printf("debug is %s\n", debug_to_stdout==0?"inactive":debug_to_stdout==2?"time stamped":"active");

	if (debug_to_stdout)
		printf("debug level set to %d\n", debug_level);

return 0;
}
