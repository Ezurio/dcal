#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dcal_api.h"
#include "sess_opts.h"
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

void print_time ( struct timeval *tv)
{
	struct tm* ptm;
	char time_string[40];
	long milliseconds;

	ptm = localtime (&tv->tv_sec);
	/* Format the date and time, down to a single second. */
	strftime (time_string, sizeof (time_string), "%Y-%m-%d %H:%M:%S", ptm);
	/* Compute milliseconds from microseconds. */
	milliseconds = tv->tv_usec / 1000;
	/* Print the formatted time, in seconds, followed by a decimal point
	   and the milliseconds. */
	printf ("%s.%03ld\n", time_string, milliseconds);
}


#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	int ret;
	struct timeval tv;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "time_test";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	ret = dcal_time_get(session, &tv.tv_sec, &tv.tv_usec);
	if (ret) printf("error in dcal_time_get(): %s\n",dcal_err_to_string(ret));
	else {
		printf("remote time:\n");
		print_time(&tv);
	}

	#define badfqdn "pool.ntp.org@"
	#define goodfqdn "pool.ntp.org"
	ret = dcal_ntpdate(session, badfqdn);
	if (ret) printf("error in dcal_ntpdate("badfqdn"): %s\n",
	                          dcal_err_to_string(ret));

	ret = dcal_ntpdate(session, goodfqdn);
	if (ret) printf("error in dcal_ntpdate("goodfqdn"): %s\n",
	                          dcal_err_to_string(ret));

	ret = dcal_time_get(session, &tv.tv_sec, &tv.tv_usec);
	if (ret) printf("error in dcal_time_get(): %s\n",dcal_err_to_string(ret));
	else {
		printf("remote time:\n");
		print_time(&tv);
	}

	ret = dcal_time_set(session, 1000000, 0);
	if (ret) printf("error in dcal_time_set(): %s\n",dcal_err_to_string(ret));

	ret = dcal_time_get(session, &tv.tv_sec, &tv.tv_usec);
	if (ret) printf("error in dcal_time_get(): %s\n",dcal_err_to_string(ret));
	else {
		printf("remote time:\n");
		print_time(&tv);
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
