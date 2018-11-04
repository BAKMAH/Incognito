#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h> // task_struct definition
#include <asm/unistd.h>
#include <linux/list.h>
#include <linux/init_task.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);
module_init(incognito_init);
module_exit(incognito_exit);

int __init incognito_init(void) {
  printk("incognito: module loaded\n");
  return 0;
}

void __exit incognito_exit(void) {
  printk("incognito: module removed\n"); 
}
