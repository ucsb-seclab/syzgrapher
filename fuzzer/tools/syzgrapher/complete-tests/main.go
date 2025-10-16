package main

import (
	"fmt"
	"math/rand"
	"os"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: complete-tests <os> <arch> <seed> <mut_idx> <prog> <verbose>")
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	seed := int(0)
	fmt.Sscanf(os.Args[3], "%d", &seed)
	fmt.Println("Seed:", seed)

	mutIdx := int(0)
	fmt.Sscanf(os.Args[4], "%d", &mutIdx)
	fmt.Println("Mutant index:", mutIdx)

	data, err := os.ReadFile(os.Args[5])
	if err != nil {
		fmt.Printf("Error while reading file: %v", err)
		os.Exit(1)
	}

	// Quick deserialize so we can fail early if the program is invalid.
	p, err := target.Deserialize([]byte(data), prog.NonStrict)
	if err != nil {
		fmt.Printf("Error while deserializing program: %v", err)
		os.Exit(1)
	}
	_ = p

	// TODO get enabled
	enabled := make(map[*prog.Syscall]bool)
	for _, c := range target.Syscalls {
		enabled[c] = true
	}
	schema := target.ComputeBaseSchema()
	schema.ApplySyscallFilter(enabled)

	verbose := false
	if len(os.Args) == 7 {
		verbose = true
	}

	for i := 0; i < 20; i++ {
		p, err := target.Deserialize([]byte(data), prog.NonStrict)
		if err != nil {
			fmt.Printf("Error while deserializing program: %v", err)
			os.Exit(1)
		}

		graph := prog.ProgToGraph(p)

		r := rand.New(rand.NewSource(int64(seed + i)))
		ctx := prog.GraphMutationContext{
			TargetSchema: schema,
			Rand:         r,
			Verbose:      verbose,
			MaxNodes:     10,
			FreqReuse:    1.0,
		}

		graph.DebugPrint()

		switch mutIdx {
		case 0:
			graph.MutateSpliceIn(&ctx)
		case 1:
			graph.MutateSpliceOut(&ctx)
		case 2:
			graph.MutateCrosslink(&ctx)
		case 3:
			graph.MutatePriority(&ctx)
		case 4:
			graph.MutateIsolateGraph(&ctx)
		case 5:
			graph.MutateReplaceConstructor(&ctx)
		}

		graph.Sanitize()
		graph.TrimToMax(&ctx)

		fmt.Println("-----")
		for _, node := range graph.Nodes {
			syscall := "<none>"
			if node.Meta != nil {
				syscall = node.Meta.Name
			}
			fmt.Println("syscall: ", syscall, " node: ", node)
		}
		fmt.Println("-----")

		p2 := prog.GraphToProg(graph)

		fmt.Println("-----")
		for _, call := range p2.Calls {
			fmt.Println("syscall: ", call.Meta.Name, " call: ", call)
		}
		fmt.Println("-----")

		prog2 := string(p2.Serialize()[:])
		fmt.Printf("-----\nMutant (%v): \n%v\n", (seed + i), prog2)
	}
}
