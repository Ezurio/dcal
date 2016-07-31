//the component value should not change
#define DCAL_LAIRD_COMPONENT    91

//the next three values define the API version between DCAL and DCAS
#define LAIRD_SDK_MSB       3
#define LAIRD_DCAL_MAJOR    1
#define LAIRD_DCAL_MINOR    1

// the following #DEFINES should not be modified by hand
// -----------------------------------------------------
#define STR_VALUE(arg) #arg
#define ZVER(name) STR_VALUE(name)

#define DCAL_VERSION_STR ZVER(LAIRD_SDK_MSB) "." ZVER(LAIRD_DCAL_MAJOR) "." ZVER(LAIRD_DCAL_MINOR)
#define DCAL_VERSION ((LAIRD_SDK_MSB << 16) | (LAIRD_DCAL_MAJOR << 8) | LAIRD_DCAL_MINOR)
#define DCAL_COMPONENT_VERSION ((DCAL_LAIRD_COMPONENT << 24) | (LAIRD_SDK_MSB << 16) | (LAIRD_DCAL_MAJOR << 8) | LAIRD_DCAL_MINOR)
// -----------------------------------------------------
