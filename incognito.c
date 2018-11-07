#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h> // task_struct definition
#include <asm/unistd.h>
#include <linux/list.h>
#include <linux/init_task.h>
#include <linux/kobject.h>
#include <linux/syscalls.h>
#include <linux/slab.h>


MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);
module_init(incognito_init);
module_exit(incognito_exit);

#ifndef __KERNEL__
#define __KERNEL__
#endif

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

psize *sys_call_table;
psize **find(void) {
 psize **sctable;
 psize i = START_CHECK;
 while (i < END_CHECK) {
  sctable = (psize **) i;
  if (sctable[__NR_close] == (psize *) sys_close) {
   return &sctable[0];
  }
  i += sizeof(void *);
 }
 return NULL;
}


int __init incognito_init(void) {
  //these two lines hide the module
  //list_del_init(&__this_module.list);
  //kobject_del(&THIS_MODULE->mkobj.kobj);

  //find system call table address
  if ((sys_call_table = (psize *) find())) {
    printk("incognito: sys_call_table found at %p\n",sys_call_table);
  } else {
    printk("incognito: sys_call_table not found\n");
  }
  printk("incognito: module loaded\n");
  return 0;
}

void __exit incognito_exit(void) {
  printk("incognito: module removed\n");
}
