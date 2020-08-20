package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <net/inet_sock.h>
#include <linux/netfilter/x_tables.h>

typedef struct {
	u32 pid;
	int ret;
} route_evt_t;

BPF_PERF_OUTPUT(route_evt);

// Arg stash structure
struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
};
BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);


/**
 * Common iptables functions
 */
static int __ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    // stash the arguments for use in retprobe
    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    cur_ipt_do_table_args.update(&pid, &args);
    return 0;
};

static int __ipt_do_table_out(struct pt_regs * ctx)
{
    // Load arguments
	int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();
    struct ipt_do_table_args *args;
    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
    {
        return 0; // missed entry
    }
    cur_ipt_do_table_args.delete(&pid);

	// Built event for userland
    route_evt_t evt = {
		.pid = pid,
		.ret = ret,
	};

    // Send event
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}


/**
 * Attach to Kernel iptables main function
 */

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ipt_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
`

type iptableEvent struct {
	Pid         uint32
	ReturnValue int32
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	table := bpf.NewTable(m.TableId("route_evt"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event iptableEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			fmt.Printf("Time %d (return value: %d)\n", event.Pid, event.ReturnValue)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
