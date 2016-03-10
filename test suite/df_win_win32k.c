/*
 * newcase.c
 *
 *  Created on: 2016年3月3日
 *      Author: wpf
 */

#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include <stdlib.h>

#define TAG_SMS_CAPTURE 0

typedef struct test{
	char *lpData;
	unsigned int cbData;

}MY_STRUCT;
typedef  MY_STRUCT* PMY_STRUCT;

void* UserAllocPoolWithQuota(unsigned int len, unsigned int flag){
	return malloc(len);
}

/* fake function, just invoke the callback function to add taints*/


void win32k_entry_point( void *lParam){

	unsigned int len = INI();
	char * data = INI();
	//..
	PMY_STRUCT my_struct = (PMY_STRUCT)lParam;

	/*fake function to simulate data transfer from user to kernel in Windows*/
	__get_user(data, &my_struct->lpData); // fetch of another value, but didn't cause disturbance

	if(data != NULL){

		__get_user(len, &my_struct->cbData);// first fetch

		unsigned int cbCapture = sizeof(MY_STRUCT) + len;

		char* my_allocation = UserAllocPoolWithQuota(cbCapture, TAG_SMS_CAPTURE);

		if (my_allocation != NULL){
			//..
			__get_user(len, &my_struct->cbData);         //second fetch

			RtlCopyMemory(my_allocation, data, len);    //use
		}

	}

	//...

}


