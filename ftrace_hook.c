#define _POSIX_C_SOURCE 199309L
#define pr_fmt(fmt) "MONITORING: " fmt
#define STRING_SIZE 1000
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/types.h>

#define ERR 1
MODULE_DESCRIPTION("exec");
MODULE_AUTHOR("Egor Panafidin");
MODULE_LICENSE("GPL");


typedef struct {
	char* name;
	int ppid;
	int pid;
	int exec_amount;
} application;


application apps[10000];
int len_apps = 0;


void *orig_exec;
void *my_exec;
unsigned long address;
struct ftrace_ops ops;



static char *get_filename(const char __user *filename)
{
	char *name;

	name = kmalloc(4096, GFP_KERNEL);

	if (strncpy_from_user(name, filename, 4096) < 0) {
		kfree(name);
		return NULL;
	}

	return name;
}

static asmlinkage long (*original_exec)(struct pt_regs *regs);

void check_processes(int pid) {
	int i;
	for(i = 0; i < len_apps; i++) {
		if (apps[i].pid == pid) {
			apps[i].exec_amount += 1;
			break;
		}
			
	}
}




void check_parents(struct task_struct *p) {
	int pid;
	int i;
	while (p->parent != &init_task) {
		pid = p->parent->pid;
		
		for(i = 0; i < len_apps; i++) {
			if (apps[i].pid == pid) {
				apps[i].exec_amount += 1;
				break;
			}
				
		}
		p = p->parent;
	}

}





static int find_original_exec(void)
{
	struct kprobe kp = {
		.symbol_name = "__x64_sys_execve"
	};

	register_kprobe(&kp);

	address = kp.addr;
	unregister_kprobe(&kp);
	if (!address) {

		return -ENOENT;
	}

	*((unsigned long*)orig_exec) = address + MCOUNT_INSN_SIZE;

	return 0;
}

static void notrace callback_func(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);

	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)my_exec;
}

void print_table(void) {
	pr_info("--------------------------------------------");
	pr_info("|%30s|%7s|%7s|%14s|\n", "FILE", "PID","PPID", "CHILDREN EXECS");
	int i;
	for(i = 0; i < len_apps; i++) {
		pr_info("|%30.30s|%7d|%7d|%14d|\n", apps[i].name, apps[i].pid, apps[i].ppid, apps[i].exec_amount);
	}
}


static asmlinkage long my_exec_func(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;

	kernel_filename = get_filename((void*) regs->di);

	char kmsg[STRING_SIZE];
	
	ret = original_exec(regs);

	check_parents(current);

	apps[len_apps].name = kernel_filename;
	apps[len_apps].ppid = current->parent->pid;
	apps[len_apps].exec_amount = 0;
	apps[len_apps].pid = current->pid;

	len_apps++;

	print_table();

	return ret;
}


static int module_load(void)
{

	orig_exec = &original_exec;

	my_exec = my_exec_func;

	if (find_original_exec())
		return ERR;

	ops.func = callback_func;

	ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	if (ftrace_set_filter_ip(&ops, address, 0, 0)) {

		return ERR;
	}

	if (register_ftrace_function(&ops)) {

		ftrace_set_filter_ip(&ops, address, 1, 0);
		return ERR;
	}
	pr_info("LKM loaded\n");

	return 0;
}


static void module_unload(void)
{

	unregister_ftrace_function(&ops);

	ftrace_set_filter_ip(&ops, address, 1, 0);

	pr_info("LKM unloaded\n");

}

module_init(module_load);
module_exit(module_unload);
