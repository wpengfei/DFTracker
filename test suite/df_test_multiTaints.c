/*
 * df_test_multiTaints.c
 *
 *  Created on: 2016年3月6日
 *      Author: wpf
 */


#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include <stdlib.h>

#define BUF_SIZE 1024

typedef struct MSG_s{
	char *text;
	unsigned int len ;

}MSG;
/* fake function, just invoke the callback function to add taints*/
signed long copy_from_user(void * to, const void *from, unsigned long n){
/*
	unsigned long temp = 0;
	for(unsigned long i = 0; i < n; i++){
		*((uint8_t*)to + temp) = *((uint8_t*)from + temp);
		temp = temp + 8;
	}

*/
	return 0;
}
unsigned int get_user(int x, int* ptr){
	//x = *ptr;
	return 0;
}


void sys_call( MSG *uptr, int n, int* up){


	unsigned int count = INIT_VALUE();
	unsigned int msglen = INIT_VALUE();


	get_user(msglen, &(uptr->len)); // first read from user, t1

	get_user(count, up); // disturbance fetch, value from other address

	//..

	char* buf = malloc(msglen); //
	if( buf != NULL){
		//..

		get_user(count, up); // disturbance fetch, value from other address
		copy_from_user(buf, uptr, count); // disturbance use

		get_user(msglen, &(uptr->len)); // second read from user, t2
		copy_from_user(buf, uptr, msglen); // real DF use
	}

		get_user(msglen, &(uptr->len)); // disturbance fetch, do not in taint controlled branch
		copy_from_user(buf, uptr, msglen); //disturbance use

	//...
}

