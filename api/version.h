//nothing in this file should change.  Its either set in stone or
//set from external values

#ifndef LAIRD_SDK_MSB
#error "error: API version defines not present"
#endif

#define LAIRD_COMPONENT    91

#define STR_VALUE(arg) #arg
#define ZVER(name) STR_VALUE(name)

#define DCAL_VERSION_STR ZVER(LAIRD_SDK_MSB) "." ZVER(LAIRD_DCAL_MAJOR) "." ZVER(LAIRD_DCAL_MINOR)
#define DCAL_VERSION ((LAIRD_SDK_MSB << 16) | (LAIRD_DCAL_MAJOR << 8) | LAIRD_DCAL_MINOR)
#define DCAL_COMPONENT_VERSION ((LAIRD_COMPONENT << 24) | (LAIRD_SDK_MSB << 16) | (LAIRD_DCAL_MAJOR << 8) | LAIRD_DCAL_MINOR)
// -----------------------------------------------------
