#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

void print_int_as_4_bytes(char * str, int val)
{
	printf("%s: %d.%d.%d.%d\n", str, (val&0xff000000)>>24, (val&0xff0000)>>16, (val&0xff00)>>8, val&0xff);
}

const char * chipset_to_string(unsigned int cs)
{
	switch(cs)
	{
		case RADIOCHIPSET_SDC10: return "10"; break;
		case RADIOCHIPSET_SDC15: return "15"; break;
		case RADIOCHIPSET_SDC30: return "30"; break;
		case RADIOCHIPSET_SDC40L: return "40L"; break;
		case RADIOCHIPSET_SDC40NBT: return "40NBT"; break;
		case RADIOCHIPSET_SDC45: return "45"; break;
		case RADIOCHIPSET_SDC50: return "50"; break;
		case RADIOCHIPSET_NONE:
		default:
			return "no hardware detected";
	}
}

int main (int argc, char *argv[])
{
	DCAL_ERR ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "versions_test";

	if((ret = session_connect_with_opts(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction

	DCAL_VERSION_STRUCT versions;
	ret = dcal_device_version( session, &versions );
	if (ret != DCAL_SUCCESS)
		printf("unable to read versions\n");
	else {
		printf("Versions:\n");
		print_int_as_4_bytes("\tSDK", versions.sdk);
		print_int_as_4_bytes("\tdriver", versions.driver);
		print_int_as_4_bytes("\tDCAS", versions.dcas);
		print_int_as_4_bytes("\tDCAL", versions.dcal);
		printf("\tChipset: %s", chipset_to_string(versions.chipset));
		if (LRD_SYSTEM_family(versions.sys)==LRD_SYS_FAM_WB)
			printf(" Workgroup Bridge");
		printf("\n");
		printf("\tfirmware: %s\n", versions.firmware);
		printf("\tsupplicant: %s\n", versions.supplicant);
		printf("\trelease: %s\n", versions.release);

	}

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}
