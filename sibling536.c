#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/types.h>
#include <linux/errno.h>

#define __SIBLINGS_DEBUG    1

/*
 * int getsiblings(pid_t pid, pid_t * pidbuf, int capacity)
 *
 * Returns:
 *   * Number of siblings whose pid's used to fill pidbuf (not greater than capacity).
 *   * -EPERM on permisson denial
 *   * -ESRCH on no such process with pid found
 *   * -EINVAL if pidbuf is NULL or capacity <= 0
 */
SYSCALL_DEFINE3(getsiblings, pid_t , pid, pid_t __user *, pidbuf, int, capacity) {
    int index;
    uid_t user_id, proc_user_id;
    struct task_struct *p, *c;

    if (__SIBLINGS_DEBUG) printk("getsiblings() EPERM = %d, ESRCH = %d, EINVAL = %d\n\n", EPERM, ESRCH, EINVAL);
    if (__SIBLINGS_DEBUG) printk("getsiblings(): pid: %d, pidbuf: %p, capacity: %d, current: %p\n", pid, pidbuf, capacity, current);

    if (capacity <= 0) {
        if (__SIBLINGS_DEBUG) printk("capacity = %d <= 0, returning -EINVAL (%d)", capacity, -EINVAL);
        return -EINVAL;
    }

    if  (NULL == pidbuf) {
        if (__SIBLINGS_DEBUG) printk("pidbuf = %p == NULL, returning -EINVAL (%d)", pidbuf, -EINVAL);
        return -EINVAL;
    }

    // START SYNC
    if (__SIBLINGS_DEBUG) printk("getsiblings(): locking tasklist_lock...\n");
    
    read_lock(&tasklist_lock);
    
    if (__SIBLINGS_DEBUG) printk("getsiblings(): locking tasklist_lock OK\n");

    user_id = current->real_cred->uid.val;

    if (pid == 0)
        p = current;
    else {
        p = find_task_by_vpid(pid);

        if (NULL == p) {
            if (__SIBLINGS_DEBUG) printk("getsiblings(): p == %p, returning -ESRCH\n", p);
            if (__SIBLINGS_DEBUG) printk("getsiblings(): unlocking tasklist_lock...\n");
            
            read_unlock(&tasklist_lock);
            
            if (__SIBLINGS_DEBUG) printk("getsiblings(): unlocking tasklist_lock OK\n");
            
            return -ESRCH;
        }
    }

    proc_user_id = p->real_cred->uid.val;

    if (__SIBLINGS_DEBUG) printk("getsiblings(): current->real_cred->uid.val = %d\n", user_id);
    if (__SIBLINGS_DEBUG) printk("getsiblings(): p->real_cred->uid.val = %d\n", proc_user_id);

    if ((user_id != 0) && (proc_user_id != user_id)) {
        if (__SIBLINGS_DEBUG) printk("getsiblings(): returning -EPERM\n");
        if (__SIBLINGS_DEBUG) printk("getsiblings(): unlocking tasklist_lock...\n");
        
        read_unlock(&tasklist_lock);
        
        if (__SIBLINGS_DEBUG) printk("getsiblings(): unlocking tasklist_lock OK\n");
        
        return -EPERM;
    }

    index = 0;

    list_for_each_entry(c, &p->sibling, sibling) {
        if (index >= capacity)
            break;

        if (0 != c->pid)
            pidbuf[index++] = c->pid;
    }

    // END SYNC
    if (__SIBLINGS_DEBUG) printk("getsiblings(): unlocking tasklist_lock...\n");

    read_unlock(&tasklist_lock);
    
    if (__SIBLINGS_DEBUG) printk("getsiblings(): unlocking tasklist_lock OK\n");
    if (__SIBLINGS_DEBUG) printk("getsiblings(): OK. Returning %d\n", index);
    return index;
}
