#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernal.h>

MODULE_LICENSE("GPL");

int incognito_init(void);
void incognito_exit(void);
module_init(incognito_init);
module_exit(incognito_exit);

int incognito_init(voud) {
  printk("incognito: module loaded\n");
  return 0;
}

void incognito_exit(void) {
  printk("incognito: module removed\n"); 
}
