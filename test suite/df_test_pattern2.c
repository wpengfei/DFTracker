/*
 * newcase3.c
 *
 *  Created on: 2016年3月5日
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


void sys_call( MSG *uptr, int n){


	unsigned int msglen = INIT_VALUE();
	get_user(msglen, &(uptr->len)); // first read from user, t1

	unsigned int copy_len = msglen - 4; // calculat args, pass t1 to copy_len

	//..
	//..
	get_user(msglen, &(uptr->len)); // second read from user, t2

	char* buf = malloc(msglen); //
	if( buf != NULL){
		//..
		//..

		copy_from_user(buf, uptr, copy_len); // if msglen - 4 < copy_len, then a buffer overflow occurs
	}

	//...
}


