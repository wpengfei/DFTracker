/*
 * df_test_embeddedFuncs.c
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
unsigned long copy_from_user(void * to, const void *from, unsigned long n){

	*(char*)to = *(char*)from;
	return 0;
}
unsigned int get_user(int x, int *ptr){
	x = *ptr;
	return 0;
}

unsigned int inner_func(MSG *uptr){
	unsigned int msglen = INIT_VALUE();

	get_user(msglen, &(uptr->len)); // first read from user, t1
	return msglen + 4;
}

void sys_call( MSG *uptr, unsigned int n){

	char* buf = malloc(BUF_SIZE);
	unsigned int msglen = INIT_VALUE();

	//get_user(msglen, &(uptr->len));
	unsigned int total_len = inner_func(uptr);

	if(total_len < BUF_SIZE){
		//..
		//..
		get_user(msglen, &(uptr->len)); // second read from user, t2
		//..

		copy_from_user(buf, uptr->text, msglen);// real use
	}

	//...
}




