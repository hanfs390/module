//##include <net/sock.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/string.h>
#include "exmpl_genl.h"
#if 0
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
#endif

/* family definition */
static struct genl_family family = {
        .hdrsize = 0,
        .name = "EXMPL",
        .version = 2,
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
        [EXMPL_A_MSG] = { .type = NLA_STRING },
        [EXMPL_A_PRINT] = { .type = NLA_STRING },
};

static int genl_fill_string_reply(struct sk_buff *msg, u32 portid, u32 seq, int flags, char * reply_data)
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
static int genl_fill_int_reply(struct sk_buff *msg, u32 portid, u32 seq, int flags, int reply)
{
	void *hdr;

	/* Add generic netlink header to netlink message */
	hdr = genlmsg_put(msg, 0, seq, &family, flags, EXMPL_C_PRINT);
	if (!hdr)
		goto out;

	rtnl_lock();
	if (nla_put_u32(msg, EXMPL_A_PRINT, reply))
		goto nla_put_failure;
	rtnl_unlock();
	genlmsg_end(msg, hdr);
	printk("sendreply\n");
	return 0;

nla_put_failure:
	rtnl_unlock();
	genlmsg_cancel(msg, hdr);
out:
	return -EMSGSIZE;
}
/* doit handler */
int exmpl_print(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	char * data = NULL;
	int rc = -ENOBUFS;
	data = nla_data(info->attrs[EXMPL_A_PRINT]);
	if (data == NULL)
		return -EINVAL;
        if (data[nla_len(info->attrs[EXMPL_A_PRINT]) - 1] != '\0')
		return -EINVAL;
	printk("print : %s\n", data);
	
	/* alloc a netlink message */
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return rc;
	rc = genl_fill_int_reply(msg, info->snd_portid, info->snd_seq, 0, 1);
	if (rc < 0)
		goto out_free;

	return genlmsg_reply(msg, info);
out_free:
	nlmsg_free(msg);
	return rc;
}
/* doit handler */
int exmpl_echo(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	char * data = NULL;
        char reply_data[10];
	int rc = -ENOBUFS;
	printk("%s\n", __func__); 
        data = nla_data(info->attrs[EXMPL_A_MSG]);
        if ((data == NULL) || (data[nla_len(info->attrs[EXMPL_A_MSG]) - 1] != '\0'))
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

	rc = genl_fill_string_reply(msg, info->snd_portid, info->snd_seq, 0, reply_data);
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
	{
		.cmd = EXMPL_C_PRINT,
		.flags = 0,
        	.policy = exmpl_genl_policy,
       		.doit = exmpl_print,
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



