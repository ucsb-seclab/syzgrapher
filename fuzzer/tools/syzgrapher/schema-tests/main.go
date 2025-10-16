package main

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: %s <os> <arch>", os.Args[0])
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Computing base schema for %v/%v\n", os.Args[1], os.Args[2])
	s := target.ComputeBaseSchema()
	fmt.Printf("Done\n")
	_ = s
}
