package main

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: tests <progfile> <os> <arch> [-d]")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error while reading logfile: %v", err)
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		fmt.Printf("Error while deserializing program: %v", err)
		os.Exit(1)
	}

	prog1 := string(p.Serialize()[:])
	fmt.Printf("Program: \n%v\n", prog1)

	graph := prog.ProgToGraph(p)
	fmt.Println("Built graph!")

	if len(os.Args) == 5 {
		// print Graph
		for i, node := range graph.Nodes {
			fmt.Printf("Node %v:\tinputs: %v\n\toutputs: %v\n", i, node.Inputs, node.Outputs)
			fmt.Printf("\tLen of Context: %v\n", len(node.Context))
		}
	}

	p2 := prog.GraphToProg(graph)
	fmt.Println("Built program!")

	// check correctness of p2
	prog2 := string(p2.Serialize()[:])
	fmt.Printf("After Conversion:\n%v\n", prog2)
	if len(prog1) == len(prog2) {
		for i := range prog2 {
			if prog1[i] != prog2[i] {
				panic(fmt.Sprintf("Programs are not equal! (byte %v)", i))
			}
		}
	} else {
		panic("Programs are not equal! (length)")
	}

}
