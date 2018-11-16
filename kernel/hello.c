#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
MODULE_LICENSE("GPL");
static int __init lkp_init(void)
{
    printk(KERN_ALERT "Hello World!\n");
    return 0;
}
static void __exit lkp_cleanup(void)
{
    printk(KERN_ALERT "Bye World!\n");
}
module_init(lkp_init);
module_exit(lkp_cleanup);
MODULE_AUTHOR("heyutao");
MODULE_DESCRIPTION("hello");
