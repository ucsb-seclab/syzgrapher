package main

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: tests <os> <arch> [<syscall>]")
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	if len(os.Args) == 4 {
		open_syscall := target.SyscallMap[os.Args[3]]
		sigs := open_syscall.SampleSignatures(target)
		for _, sig := range sigs {
			fmt.Printf("Signature for %v: %+v\n", os.Args[3], sig)
		}
	}

	done := make(chan int)
	threads := 24
	perThread := len(target.Syscalls) / threads + 1
	for i := 0; i < threads; i++ {
		t, _ := prog.GetTarget(os.Args[1], os.Args[2])
		go calcSigs(done, perThread, i, t)
	}

	totalDone := 0
	for totalDone != len(target.Syscalls) {
		totalDone += <-done
		fmt.Printf("Done %d/%d\n", totalDone, len(target.Syscalls))
	}
	/*
	fmt.Printf("Testing stability\n")
	for i, syscall := range target.Syscalls {
		fmt.Printf("Tackling syscall %v/%v - %v\n", i, len(target.Syscalls), syscall.Name)
		syscall.SampleSignatures(target)
		fmt.Printf("Done\n")
	}
	*/
}

func calcSigs(done chan int, perThread int, thread int, target *prog.Target) {
	newly_done := 0
	for i := 0; i < perThread; i++ {
		ind := thread*perThread + i
		if ind >= len(target.Syscalls) {
			break
		}
		syscall := target.Syscalls[ind]
		syscall.SampleSignatures(target)
		/*
		sig := syscall.SampleSignatures(target)
		if sig != nil && len(sig) != 0 {
			fmt.Printf("Signature for %v: in %+v, out %+v\n",sig[0].Syscall.Name, sig[0].Inputs, sig[0].Outputs)
		}
		*/
		newly_done++
		if newly_done == 10 {
			done <- newly_done
			newly_done = 0
		}
	}
	done <- newly_done
}
