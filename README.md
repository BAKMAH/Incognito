# Incognito
A simple rootkit for simple folks. 

**Authors:** Kordell Stewart, Suvaion Das, Alex Hassenbein  

This basic rootkit works on the Linux operating system and is a loadable kernel module which when loaded into the kernel (by the attacker with root privileges) will do the following:

  - Grant root privileges to a userland process
  - Hide process by PID
  - Unhide a previously hidden process by PID
  - Hide files or directories by their name
  - Unhide previously hidden files or directories
  - Hide itself
  - Unhide itself
  - Protect against being unloaded by the user
  - Disable the unload protection

#Resources
