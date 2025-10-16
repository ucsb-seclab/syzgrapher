package main

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/syzgrapher"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %v <dir>", os.Args[0])
		os.Exit(1)
	}
	t, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		fmt.Printf("GetTarget failed: %v", err)
		os.Exit(1)
	}

	dir := os.Args[1]
	gct := syzgrapher.ParseDepInfo(dir, t)

	//gct.DebugPrint()
	ct := t.BuildChoiceTable(nil, nil)
	p := &prog.Prog{
		Target: t,
	}
	p.Calls = append(p.Calls, prog.GenerateParticularCall(ct, t.SyscallMap["socket$inet_tcp"], t)...)
	temp := prog.GenerateParticularCall(ct, t.SyscallMap["listen"], t)
	p.Calls = append(p.Calls, temp[len(temp)-1])
	temp = prog.GenerateParticularCall(ct, t.SyscallMap["accept$inet"], t)
	p.Calls = append(p.Calls, temp[len(temp)-1])
	p.Calls[1].Args[0].(*prog.ResultArg).Res = p.Calls[0].Ret
	prog.AddUses(p.Calls[0].Ret, p.Calls[1].Args[0].(*prog.ResultArg))
	p.Calls[2].Args[0].(*prog.ResultArg).Res = p.Calls[0].Ret
	prog.AddUses(p.Calls[0].Ret, p.Calls[2].Args[0].(*prog.ResultArg))
	fmt.Printf("%s\n", p.Serialize())

	gp := prog.ProgToGraph(p)
	fmt.Println("socket out: ", gct.CheckEdgeDep(gp, 0, 0), len(gp.Nodes[0].Outputs))
	fmt.Println("listen out: ", gct.CheckEdgeDep(gp, 1, 0), len(gp.Nodes[1].Outputs))
	fmt.Println("accept out: ", gct.CheckEdgeDep(gp, 2, 0), len(gp.Nodes[2].Outputs))
}
