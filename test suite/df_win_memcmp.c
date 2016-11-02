/*
 * test_win_memcmp.c
 *
 *  Created on: 2016年3月10日
 *      Author: wpf
 */

#include <stdint.h>

typedef uint32_t DWORD;
typedef uint8_t BYTE;
typedef uint32_t* PDWORD;
typedef uint8_t* PBYTE;

#define __get_user(x, y) ( get_user(x, y))

unsigned int get_user(int x, int* ptr){
	x = *ptr;
	return 0;
}



//..
int testmemcmp(const void *ptr1, const void *ptr2, uint64_t num) {
	DWORD D1 = INI();
	DWORD D2 = INI();
	while(num >= sizeof(DWORD)){
		__get_user(D1,(PDWORD)ptr1); //First fetch
		__get_user(D2,(PDWORD)ptr2); //First fetch

		if(D1 != D2){ //branch condition
			num = sizeof(DWORD);
			break;
		}
		ptr1 += sizeof(DWORD);
		ptr2 += sizeof(DWORD);
		num -= sizeof(DWORD);
	}

	while(num > 0){  //
		BYTE B1 = INI();
		BYTE B2 = INI();
		__get_user(B1,(PDWORD)ptr1); //Second fetch
		__get_user(B2,(PDWORD)ptr2); //Second fetch
		if(B1 < B2){ //use
			return -1;
		}else if(B1 > B2){ //use
			return 1;
		}
		ptr1++; ptr2++;
		num--;
	}
	return 0;
}


