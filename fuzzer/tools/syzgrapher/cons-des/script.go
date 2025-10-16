package main

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func lessSpecific(a, b []string) bool {
	if len(a) > len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ./script <os> <arch> <resource name>")
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rDesc := target.GetResourceDesc(os.Args[3])
	if rDesc == nil {
		fmt.Println("Resource not found")
		os.Exit(1)
	}

	fmt.Println("Constructors")
	for _, ctor := range rDesc.Ctors {
		fmt.Println(target.Syscalls[ctor.Call].Name, ctor.Precise)
	}


	fmt.Println("Users")
	for _, s := range target.Syscalls {
		for _, inp := range s.GetInputResources(target) {
			if inp.Name == os.Args[3] || lessSpecific(inp.Kind, rDesc.Kind) {
				fmt.Println(s.Name)
			}
		}
	}
}
