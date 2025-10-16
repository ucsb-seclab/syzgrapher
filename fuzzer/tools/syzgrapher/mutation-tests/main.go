package main

import (
	"bytes"
	"encoding/gob"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime/pprof"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/syzgrapher"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type ProgStats struct {
	DepWeight float64
}

func computeStats(schema *prog.TargetSchema, gct *prog.GraphChoiceTable, g *prog.GraphProg) ProgStats {

	// Compute the weight of the graph
	depWeight := float64(0)
	count := 0
	for _, node := range g.Nodes {
		for _, input := range node.Inputs {
			if input.NodeIdx < 0 {
				continue
			}

			sysA := node.Meta.ID
			pathA := input.Path

			sysB := g.Nodes[input.NodeIdx].Meta.ID
			pathB := g.Nodes[input.NodeIdx].Outputs[input.ConnIdx].Path

			w := gct.GetScore(sysA, sysB, pathA, pathB)
			depWeight += float64(w)
			count++
		}
	}

	if count > 0 {
		depWeight /= float64(count)
	}

	stats := ProgStats{
		DepWeight: depWeight,
	}

	return stats
}

func hasMissing(g *prog.GraphProg) bool {
	for node_idx, node := range g.Nodes {
		for input_idx, input := range node.Inputs {
			if input.NodeIdx == -1 {
				fmt.Printf("Missing input %v for node %v\n", input_idx, node_idx)
				return true
			}
		}
	}
	return false
}

func getProgram(target *prog.Target, data []byte) *prog.Prog {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		fmt.Printf("Error while deserializing program: %v", err)
		os.Exit(1)
	}
	return p
}

func main() {
	var fProgram = flag.String("program", "", "Path to program file (stdin if empty))")
	var fDB = flag.String("db", "", "Path to corpus.db file")
	var fSeed = flag.Int("seed", 0, "Seed")
	var fVerbose = flag.Bool("verbose", false, "Verbose")

	var fDisableGCT = flag.Bool("disable-gct", false, "Disable GCT")
	var fVanilla = flag.Bool("vanilla", false, "Vanilla")
	// var fStream = flag.Bool("stream", false, "Stream")
	var fGenerate = flag.Bool("generate", false, "Generate")

	var fOS = flag.String("os", "", "OS")
	var fArch = flag.String("arch", "", "Arch")
	var fSchema = flag.String("schema", "", "Schema file")

	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatalf("failed to create cpuprofile: %v", err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *fOS == "" || *fArch == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, err := prog.GetTarget(*fOS, *fArch)
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	var corpus []*prog.Prog

	if *fProgram != "" {
		data, err := os.ReadFile(*fProgram)
		if err != nil {
			fmt.Printf("Error while reading program: %v", err)
			os.Exit(1)
		}
		corpus = append(corpus, getProgram(target, data))
	} else if *fDB != "" {
		db, err := db.Open(*fDB, false)
		if err != nil {
			tool.Failf("failed to open database: %v", err)
		}

		for _, rec := range db.Records {
			p := getProgram(target, rec.Val)
			corpus = append(corpus, p)
		}
	}

	corpus = corpus[:1000]

	var schema *prog.TargetSchema

	if *fSchema == "" {
		schema = target.ComputeBaseSchema()
	} else {
		content, err := os.ReadFile(*fSchema)
		if err != nil {
			log.Fatalf("failed to read schema file: %v", err)
		} else {
			dec := gob.NewDecoder(bytes.NewBuffer(content))
			err = dec.Decode(schema)
			if err != nil {
				log.Fatalf("failed to decode schema: %v", err)
			}
		}
	}

	enabled := make(map[int]bool)
	enabledMeta := make(map[*prog.Syscall]bool)
	for _, c := range target.Syscalls {
		if c.Attrs.Disabled {
			continue
		}

		enabled[c.ID] = true
		enabledMeta[c] = true
	}
	schema.ApplySyscallFilter(enabled)

	// p := getProgram(target, data)

	// for _, sig := range schema.Signatures {
	// 	fmt.Println("------------------------------------------------")
	// 	fmt.Printf("Name: %v\n", target.Syscalls[sig.SyscallID].Name)
	// 	sig.DebugPrint()
	// }
	// os.Exit(0)

	// 	p1 := getProgram(target, []byte(`r0 = open(&AUTO='./abcd', 0x99, 0xff)
	// read(r0, &AUTO, 0x1234)
	// read(r0, &AUTO, 0x3456)
	// read(r0, &AUTO, 0x5678)
	// close(r0)`))

	staticGCT := syzgrapher.ParseDepInfo("./", target)
	// corpus := []*prog.Prog{p1}
	gct := schema.BuildGraphChoiceTable(corpus, staticGCT, false)
	ct := target.BuildChoiceTable(corpus, enabledMeta)

	r := rand.New(rand.NewSource(int64(0)))
	r.Seed(int64(*fSeed))
	ctx := prog.GraphMutationContext{
		TargetSchema: schema,
		Rand:         r,
		Verbose:      *fVerbose,
		MaxNodes:     40,
		FreqReuse:    1.0,
		GCT:          gct,
		History:      nil,
		CT:           ct,
		NoMutate:     make(map[int]bool),
		Corpus:       corpus,
	}
	if *fDisableGCT {
		ctx.GCT = nil
	}

	var weight float64 = 0
	var numInvalid int = 0
	var numDowncast int = 0
	var collisions int = 0
	var size int = 0

	var syscall_counts = make(map[int]int, len(target.Syscalls))

	collisionFilter := bloom.NewWithEstimates(1000000, 0.0001)

	for i := 0; i < 100000; i++ {
		if i%100 == 0 {
			var unique int = 0
			for _, count := range syscall_counts {
				if count > 0 {
					unique++
				}
			}

			fmt.Printf("Iteration %v -- Weight: %v -- Invalid: %v -- Downcast: %v -- Collisions: %v -- Size: %v -- Unique: %v/%v\n",
				i, weight/float64(i), numInvalid, numDowncast, collisions, float64(size)/float64(i), unique, len(target.Syscalls))
		}

		// if i == 4528 {
		// 	ctx.Verbose = true
		// }

		ctx.History = &prog.OriginMutatedGraph{}

		var graph *prog.GraphProg

		if *fGenerate {
			graph = prog.Generate(&ctx)
		} else {
			p := corpus[r.Intn(len(corpus))]
			p2 := p.Clone()

			if *fVanilla {
				opts := prog.MutatorOptions{
					Verbose:        ctx.Verbose,
					SyzgrapherFreq: 0,
					TraceHistory:   false,
					DisableGCT:     true,
					MaxProgramSize: 40,
				}
				p2 = p2.Mutate(r, 40, ct, ctx.NoMutate, ctx.Corpus, schema, opts, gct)
				graph = prog.ProgToGraph(p2)
			} else {
				graph = prog.ProgToGraph(p2)
				graph.Mutate(&ctx)
			}
		}

		info := graph.Export()

		stats := computeStats(schema, gct, graph)
		weight += float64(stats.DepWeight)

		for _, node := range graph.Nodes {
			syscall_counts[node.Meta.ID]++
		}

		p2 := prog.GraphToProg(graph)
		dat := p2.Serialize()

		did_collide := false
		if collisionFilter.TestAndAdd(dat) {
			collisions++
			did_collide = true
		}

		size += len(graph.Nodes)

		// fmt.Printf("DepWeight: %v\n", stats.DepWeight)
		// var bad bool = false
		for node_idx, node := range info.Nodes {
			for in_idx, input := range node.Inputs {
				if input.IsInvalid {
					// fmt.Printf("Invalid input: %v %v\n", node_idx, in_idx)
					// name := node.Meta.SyscallName
					// fmt.Printf("Syscall: %v\n", name)
					// bad = true
					numInvalid++
				}

				if input.IsDowncast {
					// fmt.Printf("Downcast input: %v %v\n", node_idx, in_idx)
					// name := node.Meta.SyscallName
					// fmt.Printf("Syscall: %v\n", name)
					// bad = true
					numDowncast++
				}
				_ = in_idx
			}
			_ = node_idx
		}

		// if *fStream {
		// 	p = p2
		// }

		_ = did_collide
		// if did_collide {
		// fmt.Printf("origin: %+v\n", ctx.History)
		// fmt.Println("-INNER------------------------------------------")
		// fmt.Println(string(dat))
		// fmt.Println("------------------------------------------------")
		// }

		// if bad {
		// 	fmt.Printf("iteration %v\n", i)

		// 	p2 = prog.GraphToProg(graph)
		// 	fmt.Println("-INNER------------------------------------------")
		// 	fmt.Println(string(p2.Serialize()))
		// 	fmt.Println("------------------------------------------------")

		// 	os.Exit(1)
		// }

		// graph = prog.ProgToGraph(p2)

		// stats := computeStats(schema, gct, graph)
		// fmt.Println(stats)
	}
}
