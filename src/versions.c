#include "session.h"
#include "debug.h"
#include "buffer.h"
#include "dcal_api.h"

#define BUF_SZ 2048

int build_query_version( flatcc_builder_t *B)
{

	flatcc_builder_reset(B);
	flatbuffers_buffer_start(B, ns(Command_type_identifier));

	ns(Command_start(B));
	ns(Command_command_add(B, ns(Commands_GETVERSION)));
	ns(Command_end_as_root(B));

	return 0;
}

int dcal_device_version_pull( laird_session_handle s,
                              unsigned int *sdk,
                              RADIOCHIPSET *chipset,
                              LRD_SYSTEM *sys,
                              unsigned int *driver,
                              unsigned int *dcas,
                              unsigned int *dcal,
                              char *firmware,
                              char *supplicant,
                              char *release)
{
	int ret = DCAL_SUCCESS;
	char buffer[BUF_SZ];
	size_t i, size = 0;
	flatcc_builder_t *B;
	ns(Version_table_t) version = NULL;
	internal_session_handle session=NULL;
	flatbuffers_thash_t buftype;

	REPORT_ENTRY_DEBUG;

	if (s==NULL)
		return REPORT_RETURN_DBG(DCAL_INVALID_PARAMETER);

	session = s;
	if (!session->builder_init)
		return REPORT_RETURN_DBG(DCAL_FLATCC_NOT_INITIALIZED);

	B = &session->builder;

	size = BUF_SZ;
	memset(buffer, 0, BUF_SZ);
	build_query_version(B);

	size = flatcc_builder_get_buffer_size(B);
	assert(size <= BUF_SZ);
	flatcc_builder_copy_buffer(B, buffer, size);

	ret = dcal_send_buffer( session, buffer, size);

// get response
	size = BUF_SZ;
	ret = dcal_read_buffer( session, buffer, &size);

	if (ret != DCAL_SUCCESS)
		return REPORT_RETURN_DBG(ret);

//is return buffer a version buffer?
	buftype = verify_buffer(buffer, size);

	if(buftype != ns(Version_type_hash)){
		DBGERROR("could not verify version buffer.  Validated as: %s\n", buftype_to_string(buftype));
		return (DCAL_FLATBUFF_ERROR);
	}

	version = ns(Version_as_root(buffer));

	if(sdk)
		*sdk = ns(Version_sdk(version));

	if(chipset)
		*chipset = ns(Version_chipset(version));

	if(sys)
		*sys = ns(Version_sys(version));

	if(driver)
		*driver = ns(Version_driver(version));

	if(dcas)
		*dcas = ns(Version_dcas(version));

	if(dcal)
		*dcal = DCAL_API_VERSION;

	if(firmware)
		strncpy(firmware, ns(Version_firmware(version)), STR_SZ);

	if(supplicant)
		strncpy(supplicant, ns(Version_supplicant(version)), STR_SZ);

	if(release)
		strncpy(release, ns(Version_release(version)), STR_SZ);

	return REPORT_RETURN_DBG (ret);
}

