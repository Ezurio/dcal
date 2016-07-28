#include <stdio.h>
#include <stdlib.h>
#include "dcal_api.h"
#include "debug.h"
#include "dcal_internal_api.h"
#include "lists.h"
#include <unistd.h>

extern int debug_to_stdout;
extern int debug_level;
const char *DCAL_ERR_to_string( DCAL_ERR code);
extern int dynamic_mem;

void dump_list(pointer_list *list);

int main ()
{
	DCAL_ERR ret;

	pointer_list *a=NULL;
	pointer_list *b=NULL;

	REPORT_ENTRY_DEBUG;

	dump_list(a);

	printf("attempting to add to a non-existing list. error: ");
	ret = add_to_list (&a, (pvoid)1);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempting to freelist that was not initialized. error: ");
	ret = freelist(&a);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempting to initialize list 'a'. error: ");
	ret = initlist (&a);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempting to initialize list 'a' again. error: ");
	ret = initlist (&a);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempting to initialize list 'b'. error: ");
	ret = initlist (&b);
	printf("%s\n", dcal_err_to_string(ret));

	dump_list(a);

	printf("attempt to add %p to 'a' list. error: ", (pvoid)1);
	ret = add_to_list(&a, (pvoid)1);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempt to add %p to 'a' list again . error: ", (pvoid)1);
	ret = add_to_list(&a, (pvoid)1);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempt to add %p to 'a' list. error: ", (pvoid)2);
	ret = add_to_list(&a, (pvoid)2);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempt to add %p to 'a' list. error: ", (pvoid)3);
	ret = add_to_list(&a, (pvoid)3);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempt to add %p to 'a' list. error: ", (pvoid)4);
	ret = add_to_list(&a, (pvoid)4);
	printf("%s\n", dcal_err_to_string(ret));

	dump_list(a);

	printf("attempt to remove %p to 'a' list. error: ", (pvoid)3);
	ret = remove_from_list(&a, (pvoid)3);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempt to remove %p to 'a' list. error: ", (pvoid)4);
	ret = remove_from_list(&a, (pvoid)4);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempt to remove %p to 'a' list. error: ", (pvoid)1);
	ret = remove_from_list(&a, (pvoid)1);
	printf("%s\n", dcal_err_to_string(ret));

	dump_list(a);

	printf("attempting to free list 'a'. error: ");
	ret = freelist (&a);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempting to free list 'a' second time. error: ");
	ret = freelist (&a);
	printf("%s\n", dcal_err_to_string(ret));

	printf("attempting to free list 'b'. error: ");
	ret = freelist (&b);
	printf("%s\n", dcal_err_to_string(ret));



	return REPORT_RETURN_DBG(0);
}
