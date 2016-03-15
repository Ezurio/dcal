#ifndef __debug_h__
#define __debug_h__

#include "dcal_api.h"
#include <stdio.h>

typedef enum _WF_LOGLEVEL {
	DCAL_DBG_NONE = 0,
	DCAL_DBG_ERROR,
	DCAL_DBG_WARNING,
	DCAL_DBG_INFO,
	DCAL_DBG_DEBUG,
	DCAL_DBG_MSGDUMP,
	DCAL_DBG_EXCESSIVE
} WF_LOGLEVEL;

#ifdef DEBUG
void DbgPrintfLvl(int level, char *format, ...);

//helpers
#define DBGERROR( format, ...)\
do { \
	DbgPrintfLvl(DCAL_DBG_ERROR, format, ##__VA_ARGS__); \
	} while (0)

#define DBGWARN( format, ...)\
do { \
	DbgPrintfLvl(DCAL_DBG_WARNING, format, ##__VA_ARGS__); \
	} while (0)

#define DBGINFO( format, ...)\
do { \
	DbgPrintfLvl(DCAL_DBG_INFO, format, ##__VA_ARGS__); \
	} while (0)

#define DBGDEBUG( format, ...)\
do { \
	DbgPrintfLvl(DCAL_DBG_DEBUG, format, ##__VA_ARGS__); \
	} while (0)

#define DBGALL( format, ...)\
do { \
	DbgPrintfLvl(DCAL_DBG_EXCESSIVE, format, ##__VA_ARGS__); \
	} while (0)

#define DbgPrintfLvl_line(lvl, fmt,...) \
        DbgPrintfLvl(lvl, "%s:%d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DbgPrintfLvl_loc(lvl, fmt,...) \
        DbgPrintfLvl(lvl, "%s:%s:%d: " fmt, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define REPORT_ENTRY_DEBUG \
	DBGDEBUG("%s: entry\n", __func__);\
	DCAL_ERR macro_var

#define REPORT_RETURN_DBG(ret) \
	(((macro_var = (ret))==DCAL_SUCCESS) ? \
		({DBGDEBUG("%s() returned DCAL_SUCCESS\n", __func__);}) : \
		({DBGERROR("%s():%d returned %s\n", __func__, __LINE__, dcal_err_to_string(macro_var));}), macro_var)

// acceptable should be a bitmask of acceptable errorcodes
// ie BIT(DCAL_INVALID_HANDLE) | BIT(DCAL_NO_NETWORK_ACCESS)
#define REPORT_RETURN_DBG_ACCEPT_ERR_CODES(ret, acceptable)\
	((BIT(macro_var=(ret)) & acceptable) || (macro_var==DCAL_SUCCESS)? \
		({DBGDEBUG("%s() returned %s\n", __func__, dcal_err_to_string(macro_var));}) : \
		({DBGERROR("%s():%d returned %s\n", __func__, __LINE__, dcal_err_to_string(macro_var));}), macro_var)

#define DUMPLOCATION {printf("%s : line %d\n", __FUNCTION__, __LINE__);}

#else //DEBUG

#define DBGERROR( format, ...)
#define DBGWARN( format, ...)
#define DBGINFO( format, ...)
#define DBGDEBUG( format, ...)
#define DBGALL( format, ...)
#define DbgPrintfLvl_line(lvl, fmt,...)
#define DbgPrintfLvl_loc(lvl, fmt,...)
#define REPORT_ENTRY_DEBUG
#define REPORT_RETURN_DBG(ret) ret
#define REPORT_RETURN_DBG_ACCEPT_ERR_CODES(ret, acceptable) ret
#define DUMPLOCATION

#endif //DEBUG

#endif //  __debug_h__
