#ifndef __COMMON_H__
#define __COMMON_H__

// return 0 on success; 1 on failure
int in_valid_set(char c);

int validate_fqdn(char *str);

void clear_and_strncpy( char * dest, const char * src, size_t size);

#endif // __COMMON_H__
