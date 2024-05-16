#ifndef __sess_opts_h__
#define __sess_opts_h__

// change applicant_name string for usage() output
extern char * application_name;

void printmsg( int lvl, char * format, ...);

#define DBGERROR( format, ...) printmsg(1, format, ##__VA_ARGS__)
#define DBGINFO( format, ...) printmsg(2, format, ##__VA_ARGS__)
#define DBGDEBUG( format, ...) printmsg(3, format, ##__VA_ARGS__)

void common_usage(char * app_name);
int session_connect_with_opts( session_handle session, int argc, char *argv[], bool connect);

#endif //__sess_opts_h__
