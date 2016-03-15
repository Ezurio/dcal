#ifdef STATIC_MEM
int dynamic_mem=0;

#else

#include <stdlib.h>
#include "dcal_internal_api.h"
#include "session.h"
#include "lists.h"
#include "debug.h"

int dynamic_mem=1;

DCAL_ERR add_to_list( pointer_list **list, pvoid handle)
{
	DCAL_ERR ret= DCAL_SUCCESS;
	pointer_list *item = NULL;
	pointer_list *curr = *list;

	if ((list==NULL) || (handle==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else {
		item = (pointer_list *)malloc(sizeof(pointer_list));
		if (item==NULL)
			ret = DCAL_NO_MEMORY;

		else {

			item->next = NULL;
			item->handle = handle;

			if (*list==NULL) // empty list;
				*list = item;
			else {
				while (curr->next!=NULL) //find end
					curr = curr->next;

				curr->next = item;
			}
		}
	}
	return ret;
}

DCAL_ERR remove_from_list( pointer_list **list, pvoid handle)
{
	DCAL_ERR ret= DCAL_SUCCESS;
	pointer_list *prev = NULL;
	pointer_list *curr = *list;
	pointer_list *item = NULL;

	if ((list==NULL) || (handle==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else {
		if(curr->handle == handle) {
			item=curr;
			*list = curr->next;
		} else {
			while(curr!=NULL){
				if(curr->handle == handle){
					item = curr;
					break;
				}
				prev = curr;
				curr = curr->next;
			}
			if ((prev) && (item))
				prev->next = item->next;
		}
	}

	if(item)
		free(item);
	else
		if (ret==DCAL_SUCCESS)
			ret = DCAL_INVALID_HANDLE;

	return ret;
}

static uint8_t valid_session_profile(pvoid handle, uint8_t session_profile)
{
	if (!session_profile)
		return ((internal_session_struct *)handle)->state;

	return ((internal_profile_struct *)handle)->valid;
}

DCAL_ERR validate_handle( pointer_list *list, pvoid handle, uint8_t session_profile)
{
	DCAL_ERR ret= DCAL_INVALID_HANDLE;
	pointer_list *curr = list;

	if ((list==NULL) || (handle==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else {
		while(curr!=NULL){
			if (curr->handle==handle) {
				if (valid_session_profile(handle, session_profile)==SESSION_ACTIVE)
					ret = DCAL_SUCCESS;
				break;
			}
			curr=curr->next;
		}
	}
	return ret;
}

#endif
