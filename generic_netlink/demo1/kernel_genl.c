//##include <net/sock.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/string.h>
/********************************the same with user**********************************************/
/* attribute type */
enum {
        EXMPL_A_UNSPEC, /* default */
        EXMPL_A_MSG,
	EXMPL_A_PRINT,
        __EXMPL_A_MAX,
};
#define EXMPL_A_MAX (__EXMPL_A_MAX - 1)
/* commands */
enum {
        EXMPL_C_UNSPEC,
        EXMPL_C_ECHO,
	EXMPL_C_PRINT,
        __EXMPL_C_MAX,
};
#define EXMPL_C_MAX (__EXMPL_C_MAX - 1)
/************************************************************************************************/


/* family definition */
static struct genl_family family = {
        .hdrsize = 0,
        .name = "EXMPL",
        .version = 1,
        .maxattr = EXMPL_A_MAX,
};



/* 
 * genl_register_family_with_ops_grps - assignemnt struct genl_ops to genl_family.ops and register family 
 */
static inline int
_genl_register_family_with_ops_grps(struct genl_family *family,
				    const struct genl_ops *ops, size_t n_ops,
				    const struct genl_multicast_group *mcgrps,
				    size_t n_mcgrps)
{
	family->module = THIS_MODULE; 
	family->ops = ops;
	family->n_ops = n_ops;
	family->mcgrps = mcgrps;
	family->n_mcgrps = n_mcgrps;
	return genl_register_family(family);
}
#define genl_register_family_with_ops(family, ops)			\
	_genl_register_family_with_ops_grps((family),			\
					    (ops), ARRAY_SIZE(ops),	\
					    NULL, 0)



/* attribute policy */
static struct nla_policy exmpl_genl_policy[EXMPL_A_MAX + 1] = {
        [EXMPL_A_MSG] = { .type = NLA_NUL_STRING },
};

static int genl_fill_reply(struct sk_buff *msg, u32 portid, u32 seq, int flags, char * reply_data)
{
	void *hdr;

	/* Add generic netlink header to netlink message */
	hdr = genlmsg_put(msg, 0, seq, &family, flags, EXMPL_C_ECHO);
	if (!hdr)
		goto out;

	rtnl_lock();
	if (nla_put_string(msg, EXMPL_A_MSG, reply_data))
		goto nla_put_failure;
	rtnl_unlock();
	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	rtnl_unlock();
	genlmsg_cancel(msg, hdr);
out:
	return -EMSGSIZE;
}
/*
 * 添加用户数据，及添加一个netlink addribute
 * @type : nlattr的type
 * @len : nlattr中的len (length of the whole nlattr)
 * @data : 用户数据
 */
static inline int genl_msg_make_usr_msg(struct sk_buff *skb, int type, void *data, int len)
{
    int rc;

    /* add a netlink attribute to a socket buffer */
    if ((rc = nla_put(skb, type, len, data)) != 0) {
        return rc;
    }
    return 0;
}

static inline int genl_msg_prepare_usr_msg(u8 cmd, size_t size, pid_t pid, struct sk_buff **skbp)
{
    struct sk_buff *skb;

    /* create a new netlink msg */
    skb = genlmsg_new(size, GFP_KERNEL);
    if (skb == NULL) {
        return -ENOMEM;
    }

    /* Add a new netlink message to an skb */
    genlmsg_put(skb, pid, 0, &family, 0, cmd);

    *skbp = skb;
    return 0;
}
/** 
* genl_msg_send_to_user - 通过generic netlink发送数据到netlink 
*
* @data: 发送数据缓存
* @len:  数据长度 单位：byte
* @pid:  发送到的客户端pid
*
* return: 
*    0:       成功 
*    -1:      失败
*/
int genl_msg_send_to_user(void *data, int len, pid_t pid)
{
    struct sk_buff *skb;
    size_t size;
    void *head;
    int rc;

    size = nla_total_size(len); /* total length of attribute including padding */

    rc = genl_msg_prepare_usr_msg(EXMPL_C_ECHO, size, pid, &skb);

    if (rc) {
        return rc;
    }

    rc = genl_msg_make_usr_msg(skb, EXMPL_A_MSG, data, len);

    if (rc) {
        kfree_skb(skb);
        return rc;
    }

    head = genlmsg_data(nlmsg_data(nlmsg_hdr(skb)));

    genlmsg_end(skb, head);

    rc = genlmsg_unicast(&init_net, skb, pid);
    if (rc < 0) {
        return rc;
    }

    return 0;
}

/* doit handler */
int exmpl_echo(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	char * data = NULL;
	char reply_data[10];	
	int rc = -ENOBUFS;

	data = nla_data(info->attrs[EXMPL_A_MSG]);
	if (data[nla_len(info->attrs[EXMPL_A_MSG]) - 1] != '\0')
		return -EINVAL;
	printk("recv the msg = %s\n", data);
	
	strcpy(reply_data, data);
	reply_data[strlen(data)] = '7';
	reply_data[strlen(data) + 1] = '\0';
	printk("reply_data = %s\n", reply_data);

	/* alloc a netlink message */
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return rc;
	rc = genl_fill_reply(msg, info->snd_portid, info->snd_seq, 0, reply_data);
	if (rc < 0)
		goto out_free;

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
	return rc;
}

/* operation definition */
struct genl_ops ops[] = { 
	{
	 	.cmd = EXMPL_C_ECHO,
        	.flags = 0,
        	.policy = exmpl_genl_policy,
       		.doit = exmpl_echo,
        	.dumpit = NULL,
	},
};

static int  __init genl_init(void)
{	
	int ret;		
	ret = genl_register_family_with_ops(&family, ops);
	if (ret) {
		printk("register genl_family error=%d\n", ret);
		return ret;
	}
	printk("genl_init\n");
	return 0;	
}	


static void __exit genl_exit(void)

{
	genl_unregister_family(&family); 
	printk("genl_exit\n");
}


module_init(genl_init);
module_exit(genl_exit);


MODULE_LICENSE("GPL");



