#!/usr/bin/env python 
from __future__ import print_function
from bcc import BPF

program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
    //create a hash named currsock , key_type is struct sock that defaults to u32
    BPF_HASH(currsock, u32, struct sock *);
    //this intruments the tcp_v4_connect function
    int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk){
        // u32 is an unsigned 32bit int , tdig = threadID
        u32 pid = bpf_get_current_pid_tgid();
        currsock.update(&pid, &sk);
        //srtruct pt_regs *ctx Registers  and BPF context
        // struct sock *sk first argument to tcp_v4_connect
        return 0;
    };
   int kretprobe__tcp_v4_connect(struct pt_regs *ctx){
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid();
        struct sock **skpp;
        skpp = currsock.lookup(&pid);
        if (skpp == 0) {
            return 0;
        }
        if ( ret != 0){
            currsock.delete(&pid);
            return 0;
        }
        // get the details
        struct sock *skp = *skpp;
        u32 saddr, daddr = 0;
        u16 dport = 0;
        bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
        bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
        //output
        // ntohs converts unsigned short int netshort from network byte order to host byte order
        bpf_trace_printk("trace_tcp4connect %x %x %d \\n", saddr, daddr, ntohs(dport));
        currsock.delete(&pid);
        return 0;
   }

"""
b = BPF(text=program)
# header
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR",
    "DPORT"))

def inet_ntoa(addr):
	dq = ''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff)
		if (i != 3):
			dq = dq + '.'
		addr = addr >> 8
	return dq

# filter and format output
while 1:
        # Read messages from kernel pipe
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(" ")
        except ValueError:
            # Ignore messages from other tracers
            continue

        # Ignore messages from other tracers
        if _tag != "trace_tcp4connect":
            continue

	print("%-6d %-12.12s %-16s %-16s %-4s" % (pid, task,
	    inet_ntoa(int(saddr_hs, 16)),
	    inet_ntoa(int(daddr_hs, 16)),
	    dport_s))
