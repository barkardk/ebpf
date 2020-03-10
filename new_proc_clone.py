#!/usr/bin/env python
from bcc import BPF

program = """

int kprobe__sys_sync(void *ctx){
    bpf_trace_printk("You forked a process\\n");
    return 0;
}
"""

BPF(text=program).trace_print()
