//nothing in this file should change.  Its either set in stone or
//set from external values

#ifndef SDC_SDK_MSB
#error "error: API version defines not present"
#endif

#define SUMMIT_COMPONENT    91

#define STR_VALUE(arg) #arg
#define ZVER(name) STR_VALUE(name)

#define DCAL_VERSION_STR ZVER(SDC_SDK_MSB) "." ZVER(DCAL_MAJOR) "." ZVER(DCAL_MINOR)
#define DCAL_VERSION ((SDC_SDK_MSB << 16) | (DCAL_MAJOR << 8) | DCAL_MINOR)
#define DCAL_COMPONENT_VERSION ((SUMMIT_COMPONENT << 24) | (SDC_SDK_MSB << 16) | (DCAL_MAJOR << 8) | DCAL_MINOR)
// -----------------------------------------------------
