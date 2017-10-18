#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "dcal_api.h"

// return 0 on success; 1 on failure
int in_valid_set(char c)
{

	if ((c >= 'a') && (c <='z')) //lower case alpha
		return 0;

	if ((c >= 'A') && (c <='Z')) //upper case alpha
		return 0;

	if ((c >= '-') && (c <='9')) //'-','.','/',digits
		return 0;

	if (c=='_')
		return 0;

	return 1;
}

int validate_fqdn(char *str)
{
	int i, len;

	if (str==NULL)
		return 0;

	len = strlen(str);

	for (i=0; i<len; i++)
		if (in_valid_set(str[i])==1)
			return 1;

	return 0;
}

void clear_and_strncpy( char * dest, const char * src, size_t size)
{
	assert(dest);
	assert(src);
	memset(dest,0,size);
	strncpy(dest, src, size);
}

