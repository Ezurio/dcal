#ifdef STATIC_MEM
int dynamic_mem=0;

#else

#include <stdlib.h>
#include <pthread.h>
#include "dcal_internal_api.h"
#include "session.h"
#include "lists.h"
#include "debug.h"

int dynamic_mem=1;

#define INIT_LOCK(x) do {((x) = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t))); pthread_mutex_init((x), NULL);} while(0)
#define DESTROY_LOCK(x) do {(pthread_mutex_destroy(x)); free(x);} while(0)
#define LOCK(x)  (pthread_mutex_lock(x))
#define UNLOCK(x) (pthread_mutex_unlock(x))

// Should only be called from an __attribute__ (constructor) function
DCAL_ERR initlist(pointer_list **list)
{
	if (list==NULL)
		return DCAL_INVALID_PARAMETER;

	// ensure we are pointing to a NULL list
	if (*list!=NULL)
		return DCAL_HANDLE_IN_USE;

	*list = (pointer_list *)malloc(sizeof(pointer_list));
	if(*list==NULL)
		return DCAL_NO_MEMORY;

	(*list)->head = NULL;
	INIT_LOCK((*list)->lock);

	return DCAL_SUCCESS;
}

// Should only be called from an __attribute__ (destructor) function
DCAL_ERR freelist(pointer_list **list)
{
	if (list==NULL)
		return DCAL_INVALID_PARAMETER;

	if (*list==NULL)
		return DCAL_INVALID_HANDLE;

	//remove any entries
	while ((*list)->head)
		remove_from_list(list, (*list)->head->handle);

	DESTROY_LOCK((*list)->lock);

	free(*list);
	*list = NULL;

	return DCAL_SUCCESS;
}

// true only if list is valid and handle is in list
bool validate_handle( pointer_list *list, pvoid handle)
{
	bool ret = false;
	list_element *le = NULL;

	if ((list!=NULL) && (handle!=NULL))
	{
		LOCK(list->lock);

		le = list->head;
		while (le) {
			if (le->handle == handle) {
				ret = true;
				break;
			}
			le = le->next;
		}

		UNLOCK(list->lock);
	}
	return ret;
}

DCAL_ERR add_to_list( pointer_list **list, pvoid handle)
{
	DCAL_ERR ret= DCAL_SUCCESS;
	list_element *item = NULL;
	list_element *curr = NULL;

	if ((list==NULL) || (*list==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if (handle==NULL)
		ret = DCAL_INVALID_HANDLE;
	else if (validate_handle(*list, handle))
		// handle is already in list
		ret = DCAL_HANDLE_IN_USE;
	else {
		item = (list_element *)malloc(sizeof(pointer_list));
		if (item==NULL)
			ret = DCAL_NO_MEMORY;

		else {
			item->next = NULL;
			item->handle = handle;
			LOCK((*list)->lock);
			if ((*list)->head==NULL) // empty list;
				(*list)->head = item;
			else {
				curr = (*list)->head;
				while (curr->next!=NULL) //find end
					curr = curr->next;

				curr->next = item;
			}
			UNLOCK((*list)->lock);
		}
	}
	return ret;
}

DCAL_ERR remove_from_list( pointer_list **list, pvoid handle)
{
	DCAL_ERR ret= DCAL_SUCCESS;
	list_element *curr = NULL;
	list_element *item = NULL;

	if ((list==NULL) || (*list==NULL) || (handle==NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if ((*list)->head == NULL)
		// empty list
		ret = DCAL_INVALID_HANDLE;
	else {
		if((*list)->head->handle == handle){
			// remove element from head
			item = (*list)->head;
			(*list)->head = item->next;
		} else {
			LOCK((*list)->lock);
			curr = (*list)->head;
			while(curr!=NULL){
				if((curr->next) && (curr->next->handle == handle)){
						item = curr->next;
						break;
					}
				curr = curr->next;
			}
			if ((curr) && (item))
				curr->next = item->next;

			UNLOCK((*list)->lock);
		}
	}

	if(item)
		free(item);
	else
		if (ret==DCAL_SUCCESS)
			// dont overwrite an already set return code
			ret = DCAL_INVALID_HANDLE;

	return ret;
}

void dump_list(pointer_list *list)
{
	list_element *le;
	if (list==NULL)
		printf("uninitialized list\n");
	else {
		LOCK(list->lock);
		if (list->head == NULL)
			printf("empty list\n");
		else {
			printf("Head: %p\n",list->head->handle);
			le = list->head;
			if(le)
				le = le->next;
			while (le) {
				printf("\titem: %p\n",le->handle);
				le = le->next;
			}
		}
		UNLOCK(list->lock);
	}
}

#endif
