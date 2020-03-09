#!/usr/bin/env python
from bcc import BPF

program = """
#include <asm/ptrace.h>
#include <linux/types.h>

int kprobe__sys_open(struct pt_regs *ctx, char __user* pathname, int flags, mode_t mode){
    bpf_trace_printk("sys_open called.\\n");
    return 0;
}
// int kprobe__sys_openat(struct pt_regs *ctx, int dirfd, char __user* pathname, int flags, mode_t mode ){
//    bpf_trace_printk("sys_openat called. \\n");
//    return 0;
// } 
   
 int kprobe__do_sys_open(struct pt_regs *ctx, int dirfd, char __user* pathname, int flags,  mode_t mode) {
   // this bpf_trace_printk is considered harmful, its like ftrace
    bpf_trace_printk("do_sys_open called: %s\\n", pathname);
    return 0;

 }   
"""
b = BPF(text=program)
b.trace_print()
