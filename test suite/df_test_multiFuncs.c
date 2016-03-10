/*
 * df_test_mutiarg.c
 *
 *  Created on: 2016年3月8日
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

	return 0;
}
unsigned int get_user(int x, int* ptr){
	x = *ptr;
	return 0;
}

void sys_call( MSG *uptr, int n){

	char* buf = malloc(BUF_SIZE);

	unsigned int msglen = INIT_VALUE();
	unsigned int err = get_user(msglen, &(uptr->len)); // first read from user, t1

	if(err)
		return;
	if(msglen < BUF_SIZE){
			//..
			//..
			get_user(msglen, &(uptr->len)); // second read from user, t2
			//..

			copy_from_user(buf, uptr->text, msglen);// real use
	}
	else{
		return;
	}

	//...

	return;
}


int kernel_func(MSG *uptr, int n, int* up){


	unsigned int count = INIT_VALUE();
	unsigned int msglen = INIT_VALUE();

	get_user(count, up); // disturbance fetch, value from other address

	get_user(msglen, &(uptr->len)); // first read from user, t1


	//..

	char* buf = (char*)malloc(msglen); //
	if( buf != NULL){
		//..
		get_user(count, up); // disturbance fetch, value from other address
		copy_from_user(buf, uptr, count); // disturbance use

		get_user(msglen, &(uptr->len)); // second read from user, t2
		copy_from_user(buf, uptr, msglen); // real DF use

		return 1;
	}
	else{
		return 0;
	}
}





