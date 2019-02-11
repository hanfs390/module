#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <linux/genetlink.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "exmpl_genl.h"
#if 0
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
/* attribute policy */
static struct nla_policy exmpl_genl_policy[EXMPL_A_MAX + 1] = {
         [EXMPL_A_MSG] = { .type = NLA_STRING },
         [EXMPL_A_PRINT] = { .type = NLA_U32 },
};

int parse_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *attrs[EXMPL_A_MAX + 1];
	int len;
	int * reply;
	char send_reply[10];

	genlmsg_parse(nlh, 0, attrs, EXMPL_A_MAX, exmpl_genl_policy);

	switch (gnlh->cmd){
		
    	case EXMPL_C_ECHO:
		
		printf("echo reply\n");		
		if (attrs[EXMPL_A_MSG]){
			len = nla_len(attrs[EXMPL_A_MSG]);
                	memcpy(send_reply, nla_data(attrs[EXMPL_A_MSG]), len);
            		printf("reply=%s\n", send_reply);
		}

           	return NL_OK;
			
	case EXMPL_C_PRINT:
		
		printf("print reply\n");		
		if (attrs[EXMPL_A_PRINT]){
                	reply = nla_data(attrs[EXMPL_A_PRINT]);
            		printf("reply=%d\n", *reply);
		}
           	return NL_OK;
		
				
       	default:
            return NL_SKIP;
        }

    return NL_OK;
	
}

int send_string(struct nl_sock *sock, int family_id, int cmd, int attr_type, char * send_msg)
{
    struct nl_msg *msg;
    int ret = 0;
    msg = nlmsg_alloc();
    if (msg == NULL)
    {
        printf("Unable to allocate message\n");
        return -1;
    }
    printf("%s\n", send_msg);
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, 0, cmd, 1);
    nla_put(msg, attr_type, (strlen(send_msg)+1), send_msg);

    ret = nl_send_auto_complete(sock, msg);
    nlmsg_free(msg);
    if (ret < 0)
    {
     	printf("nl_send_auto_complete failed\n");
        return ret;
    }
    printf("nl_send_auto_complete success,ret = %d\n",ret);
}


int  main(void)
{
    struct  nl_sock * demo_sock;
    char * send_msg = "123456";
    char * print_data = "Hello Word !";
    struct nl_msg *msg;
    int ret = 0;
    int id = 0;
    int arg = 15;

    demo_sock = nl_socket_alloc();
    if(demo_sock == NULL)
    {
        printf("Unable to allocate socket\n");
	return -1;
    }

    ret = genl_connect(demo_sock);
    if(ret < 0)
    {
		printf("genl sock connect failed\n");
		return -1;
    }

    id = genl_ctrl_resolve(demo_sock, "EXMPL");

    nl_socket_disable_seq_check(demo_sock);
    nl_socket_modify_cb(demo_sock, NL_CB_VALID, NL_CB_CUSTOM, parse_cb, &arg);
    printf("id = %d\n", id);
    
    send_string(demo_sock, id, EXMPL_C_PRINT, EXMPL_A_PRINT, print_data);
    nl_recvmsgs_default(demo_sock);
    nl_recvmsgs_default(demo_sock);
    printf("OK1\n"); 
    send_string(demo_sock, id, EXMPL_C_ECHO, EXMPL_A_MSG, send_msg);
    nl_recvmsgs_default(demo_sock);
    nl_recvmsgs_default(demo_sock); /* why it need recv twice */
    printf("OK2\n"); 
    nl_socket_free(demo_sock);
    return 0;
}





