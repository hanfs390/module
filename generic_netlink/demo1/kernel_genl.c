#include <net/sock.h>
#include <linux/module.h>

#include <linux/netlink.h>
#include <net/genetlink.h>

/* attribute type */
  enum {
        DOC_EXMPL_A_UNSPEC,
        DOC_EXMPL_A_MSG,
        __DOC_EXMPL_A_MAX,
  };
#define DOC_EXMPL_A_MAX (__DOC_EXMPL_A_MAX - 1)
#define GENL_ID_GENERATE 0
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
  /* family definition */
  static struct genl_family doc_exmpl_gnl_family = {
        .id = GENL_ID_GENERATE,
        .hdrsize = 0,
        .name = "DOC_EXMPL",
        .version = 1,
        .maxattr = DOC_EXMPL_A_MAX,

  };

/* doit handler */
int doc_exmpl_echo(struct sk_buff *skb, struct genl_info *info)
{
        /* message handling code goes here; return 0 on success, negative
         * values on failure */
	printk("echo replay");
	return 0;	
}


  /* attribute policy */
  static struct nla_policy doc_exmpl_genl_policy[DOC_EXMPL_A_MAX + 1] = {
        [DOC_EXMPL_A_MSG] = { .type = NLA_NUL_STRING },
  };

  /* commands */
  enum {
        DOC_EXMPL_C_UNSPEC,
        DOC_EXMPL_C_ECHO,
        __DOC_EXMPL_C_ECHO,
  };
  #define DOC_EXMPL_C_MAX (__DOC_EXMPL_C_MAX - 1)


int genl_recv_doit(struct sk_buff *skb, struct genl_info *info)
{
    /* doit 没有运行在中断上下文 */
    struct nlmsghdr     *nlhdr;
    struct genlmsghdr   *genlhdr;
    struct nlattr       *nlh;
    
     nlhdr = nlmsg_hdr(skb);
     genlhdr = nlmsg_data(nlhdr);
     nlh = genlmsg_data(genlhdr);
     printk("recv the message from userspace \n");
     return 0;
}

static inline int genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data, int len)
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
    genlmsg_put(skb, pid, 0, &doc_exmpl_gnl_family, 0, cmd);

    *skbp = skb;
    return 0;
}
void genl_register_ops(struct genl_family *family, const struct genl_ops *ops)
{
	family->module = THIS_MODULE;
	family->ops = ops;
	family->n_ops = ARRAY_SIZE(ops);

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

    rc = genl_msg_prepare_usr_msg(DOC_EXMPL_C_ECHO, size, pid, &skb);

    if (rc) {
        return rc;
    }

    rc = genl_msg_mk_usr_msg(skb, DOC_EXMPL_A_MSG, data, len);

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


  /* operation definition */
  struct genl_ops doc_exmpl_gnl_ops_echo = {
        .cmd = DOC_EXMPL_C_ECHO,
        .flags = 0,
        .policy = doc_exmpl_genl_policy,
        .doit = genl_recv_doit,
        .dumpit = NULL,
  };

static int  __init genl_init(void)
{	
		
	genl_register_family(&doc_exmpl_gnl_family); 
	genl_register_ops(&doc_exmpl_gnl_family, &doc_exmpl_gnl_ops_echo);
	printk("genl_demo init\n");
	return 0;	
}	


static void __exit genl_exit(void)

{
	genl_unregister_family(&doc_exmpl_gnl_family); 
	printk("genl_demo exit\n");
}


module_init(genl_init);
module_exit(genl_exit);


MODULE_LICENSE("GPL");








