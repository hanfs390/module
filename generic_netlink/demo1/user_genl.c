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

#define MAX_MSG_SIZE 128
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

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

/* attribute policy */
static struct nla_policy exmpl_genl_policy[EXMPL_A_MAX + 1] = {
         [EXMPL_A_MSG] = { .type = NLA_STRING },
};

/*
 * genl_rcv_msg - recv the msg from kernel module 
 * @family_id :  genl family id 
 * @sock : the sock of genl
 * @data : the message from kernel
 */
void genl_rcv_msg(int family_id, int sock, char *data)
{
    int ret;
    struct msgtemplate msg;
    struct nlattr *na;
    struct genlmsghdr *gnlh;
    struct nlmsghdr *nlh;
    struct nlattr *attrs[EXMPL_A_MAX + 1];
    int len;

    ret = recv(sock, &msg, sizeof(msg), 0);
    if (ret < 0) {
        return;
    }
    printf("received length %d\n", ret);

    gnlh = &msg.g;
    nlh = &msg.n;
    genlmsg_parse(nlh, 0, attrs, EXMPL_A_MAX, exmpl_genl_policy);    
    
    switch (gnlh->cmd) {
	case EXMPL_C_ECHO:
		if (attrs[EXMPL_A_MSG]){
			len = nla_len(attrs[EXMPL_A_MSG]);
			memcpy(data, nla_data(attrs[EXMPL_A_MSG]), len);
			printf("recevic data = %s\n", data);
		}

    }

} 

/** 
* genl_send_msg - 通过generic netlink给内核发送数据 
*
* @sd: 客户端socket 
* @nlmsg_type: family_id
* @nlmsg_pid: 客户端pid
* @genl_cmd: 命令类型
* @genl_version: genl版本号
* @nla_type: netlink attr类型
* @nla_data: 发送的数据
* @nla_len: 发送数据长度
*
* return: 
*    0:       成功 
*    -1:      失败
*/
int genl_send_msg(int sd, u_int16_t nlmsg_type, u_int32_t nlmsg_pid,
        u_int8_t genl_cmd, u_int8_t genl_version, u_int16_t nla_type,
        void *nla_data, int nla_len)
{
    struct nlattr *na;
    struct sockaddr_nl nladdr;
    int r, buflen;
    char *buf;

	
    msgtemplate_t msg;

    printf("send is start\n");
    if (nlmsg_type == 0) {
        return 0;
    }

    msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    msg.n.nlmsg_type = nlmsg_type;
    msg.n.nlmsg_flags = NLM_F_REQUEST;
    msg.n.nlmsg_seq = 0;
    printf("1\n"); 
    /*
     * nlmsg_pid是发送进程的端口号。
     * Linux内核不关心这个字段，仅用于跟踪消息。
     */
    msg.n.nlmsg_pid = nlmsg_pid;
    msg.g.cmd = genl_cmd;
    msg.g.version = genl_version;
    printf("2\n"); 
    na = (struct nlattr *) GENLMSG_DATA(&msg);
    na->nla_type = nla_type;
    na->nla_len = nla_len + 1 + NLA_HDRLEN;
    printf("3\n"); 
    memcpy(NLA_DATA(na), nla_data, nla_len);
    msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    printf("send msg : %s\n", (char *)nla_data);
    buf = (char *) &msg;
    buflen = msg.n.nlmsg_len ;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr
            , sizeof(nladdr))) < buflen) {
        if (r > 0) {
            buf += r;
            buflen -= r;
        } else if (errno != EAGAIN) {
            return -1;
        }
    }
    return 0;
}

static int genl_get_family_id(int sd, char *family_name)
{
    msgtemplate_t ans;
    int id, rc;
    struct nlattr *na;
    int rep_len;

    rc = genl_send_msg(sd, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, 1,
                    CTRL_ATTR_FAMILY_NAME, (void *)family_name,
                    strlen(family_name)+1);


    rep_len = recv(sd, &ans, sizeof(ans), 0);
    if (rep_len < 0) {
        return 0;
    }
    if (ans.n.nlmsg_type == NLMSG_ERROR || !NLMSG_OK((&ans.n), rep_len)) {
        return 0;
    }

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) NLA_DATA(na);
    } else {
        id = 0;
    }
   printf("id = %d\n", id);
    return id;
}

int  main(void)
{
    struct sockaddr_nl saddr;
    int                sock;
    int id;
    char * send_msg = "123456";
    int ret;
    char * data;
    char * reply; /* the attrs */
    
    reply = malloc(32);

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

    if (sock < 0) {
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = 1234;
    if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        printf("bind fail!\n");
        close(sock);
        return -1;
    }
    
    id = genl_get_family_id(sock, "EXMPL");
    if (id <= 0) {
	printf("maybe kernel register failed ! can`t find family ID\n");
    }
    
    printf("find family ID = %d by family name\n", id);
    data =(char*)malloc(256);
    if(!data)
    {
        perror("malloc error!");
        exit(1);
    }
    memset(data,0,256);
    strcpy(data,"123456");
    
    ret = genl_send_msg(sock, id, 1234, EXMPL_C_ECHO, 1, EXMPL_A_MSG, (void *)data, strlen(data) + 1);
    if (ret) {
	printf("send failed\n");
    }

    printf("send success\n");

    genl_rcv_msg(id, sock, reply);
    
    printf("recv mesg = %d\n", strlen(reply));    
    close(sock);
}





