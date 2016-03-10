/*
 * df_real_compat.c
 *
 *  Created on: 2016年3月9日
 *      Author: wpf
 */
#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include <stdlib.h>

#define EFAULT 1;
#define EINVAL 2;
#define ENOBUFS 3;

#define __user __attribute__((noderef))

#define CMSG_COMPAT_FIRSTHDR(x) ( x )
#define __get_user(x, y) ( get_user(x, y))

typedef unsigned int compat_size_t;
typedef unsigned int __kernel_size_t;

struct msghdr{ //kmsg
	unsigned int msg_controllen;
	unsigned int msg_control;

};
struct compat_cmsghdr{//ucmsg
	unsigned int cmsg_len;
	unsigned int cmsg_level;
	unsigned int cmsg_type;
};
struct cmsghdr{//kcmsg
	unsigned int cmsg_len;
	unsigned int cmsg_level;
	unsigned int cmsg_type;
};

//above are fake functions and structures, just invoke the callback function to add taints


// real code starts from here
int cmsghdr_from_user_compat_to_kern(struct msghdr *kmsg,
			       unsigned char *stackbuf, int stackbuf_size){
	struct compat_cmsghdr  __user *ucmsg;//
	struct cmsghdr *kcmsg, *kcmsg_base;
	compat_size_t ucmlen = INI();//
	__kernel_size_t kcmlen, tmp;

	kcmlen = 0;
	kcmsg_base = kcmsg = (struct cmsghdr *)stackbuf;       //[1]
	ucmsg = CMSG_COMPAT_FIRSTHDR(kmsg);

	while(ucmsg != NULL) {  // Examine the arguments in this loop
		if(get_user(ucmlen, &ucmsg->cmsg_len))            //[2]
			return -EFAULT;

		/* Catch bogons. */
		if(CMSG_COMPAT_ALIGN(ucmlen) <
		   CMSG_COMPAT_ALIGN(sizeof(struct compat_cmsghdr)))
			return -EINVAL;
		if((unsigned long)(((char  *)ucmsg - (char  *)kmsg->msg_control)//
						   + ucmlen) > kmsg->msg_controllen) //[3]
			return -EINVAL;          //Examined unmlen here, which is abcent in the second loop

		tmp = ((ucmlen - CMSG_COMPAT_ALIGN(sizeof(*ucmsg))) +
			   CMSG_ALIGN(sizeof(struct cmsghdr)));
		kcmlen += tmp;                      //[4]
		ucmsg = cmsg_compat_nxthdr(kmsg, ucmsg, ucmlen);
	}
	if(kcmlen == 0)
		return -EINVAL;

	/* The kcmlen holds the 64-bit version of the control length.
	 * It may not be modified as we do not stick it into the kmsg
	 * until we have successfully copied over all of the data
	 * from the user.
	 */
	if(kcmlen > stackbuf_size)                 //[5]
		kcmsg_base = kcmsg = kmalloc(kcmlen,GFP_KERNEL());//
	if(kcmsg == NULL)
		return -ENOBUFS;

	/* Now copy them over neatly. */
	memset(kcmsg, 0, kcmlen);
	ucmsg = CMSG_COMPAT_FIRSTHDR(kmsg);
	while(ucmsg != NULL) { //copy data from user to data in this loop
		__get_user(ucmlen, &ucmsg->cmsg_len);         //[6] second fetch of ucmlen
		tmp = ((ucmlen - CMSG_COMPAT_ALIGN(sizeof(*ucmsg))) +
			   CMSG_ALIGN(sizeof(struct cmsghdr)));
		kcmsg->cmsg_len = tmp;
		__get_user(kcmsg->cmsg_level, &ucmsg->cmsg_level);
		__get_user(kcmsg->cmsg_type, &ucmsg->cmsg_type);

		/* Copy over the data. */
		if(copy_from_user(CMSG_DATA(kcmsg),    //[7]  use of ucmlen, which can cause statck overflow
				  CMSG_COMPAT_DATA(ucmsg),
				  (ucmlen - CMSG_COMPAT_ALIGN(sizeof(*ucmsg)))))
			goto out_free_efault;

		/* Advance. */
		kcmsg = (struct cmsghdr *)((char *)kcmsg + CMSG_ALIGN(tmp));
		ucmsg = cmsg_compat_nxthdr(kmsg, ucmsg, ucmlen);
	}

	/* Ok, looks like we made it.  Hook it up and return success. */
	kmsg->msg_control = kcmsg_base;
	kmsg->msg_controllen = kcmlen;
	return 0;

out_free_efault:
	if(kcmsg_base != (struct cmsghdr *)stackbuf)
		kfree(kcmsg_base);
	return -EFAULT;

}


