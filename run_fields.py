#!/usr/bin/env python 

from bcc import BPF

program = """
int hello(void *ctx){
    bpf_trace_printk("oi\\n");
    return 0;
}

"""

b = BPF(text=program)

b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

print("%-18s %-16s %-6s %s" % ("Time(s)", "COMM", "PID", "Message"))

while 1: 
    try:
        (task,pid,cpu,flags,ts,msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
