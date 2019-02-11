#ifndef __EXMPL_GENL_H
#define __EXMPL_GENL_H


#define MAX_MSG_SIZE 128
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))
 
/* netlink message */
typedef struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char data[MAX_MSG_SIZE];
} msgtemplate_t;

/* attribute type */
enum {
        EXMPL_A_UNSPEC,
        EXMPL_A_MSG,
        EXMPL_A_PRINT,
        __EXMPL_A_MAX,
};

#define EXMPL_A_MAX (__EXMPL_A_MAX - 1)
 
/* cmd */
enum {
        EXMPL_C_UNSPEC,
        EXMPL_C_ECHO,
        EXMPL_C_PRINT,
        __EXMPL_C_ECHO,
};


#endif
