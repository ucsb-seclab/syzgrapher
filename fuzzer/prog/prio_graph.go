package prog

import (
	"fmt"
	"math/rand"
	"sort"
	"time"
)

type StaticGCT struct {
	GCTForward  *StaticGraphChoiceTable
	GCTBackward *StaticGraphChoiceTable
}

// GCT information derived from static analysis.
type StaticGraphChoiceTable struct {
	//SyscallRuns  [][]StaticEntry
	//ResourceRuns []map[string][]StaticEntry

	// (syscall_id, arg_index) -> []Entry
	ArgRuns []map[int][]StaticEntry
}

type StaticEntry struct {
	CumProb       int
	Prob          int
	CheckerName   string
	ArgCheckIndex int
	SetName       string
	ArgSetIndex   int
}

// type RunKey struct {
// 	Sig, Idx int
// }

type RunKey struct {
	SyscallID int
	Path      ResourcePath
}

// Stores resource-centric dependency weights.
//
// The two runs fields are used at runtime to efficiently sample from the distribution.
type GraphChoiceTable struct {
	runsBackward map[RunKey][]Entry
	runsForward  map[RunKey][]Entry

	// (sig_a, sig_b, out_idx_a, in_idx_b) -> weight
	prio GraphPrio

	// Keep track of syscall/resource pairs that have been seen.
	resForward  []map[ResourcePath]bool
	resBackward []map[ResourcePath]bool
}

type Entry struct {
	CumProb int
	SigIdx  int

	// Represents either the input or output index, depending on if this is in runsForward or runsBackward.
	Path ResourcePath
}

type PrioKey struct {
	SyscallA int
	SyscallB int
	OutA     ResourcePath
	InB      ResourcePath
}

type GraphPrio = map[PrioKey]int

func (gct *GraphChoiceTable) setPrio(sigA, sigB int, outA, inB ResourcePath, weight int) {
	key := PrioKey{sigA, sigB, outA, inB}
	gct.prio[key] = weight
	gct.resForward[sigA][outA] = true
	gct.resBackward[sigB][inB] = true
}

func (gct *GraphChoiceTable) getPrio(sigA, sigB int, outA, inB ResourcePath) int {
	key := PrioKey{sigA, sigB, outA, inB}
	if w, ok := gct.prio[key]; ok {
		return w
	}
	return 0
}

const (
	graphPrioLowDynamic = 0
	graphPrioLowStatic  = 0
	graphPrioHigh       = 1000
)

// Constructs a GraphChoiceTable using static analysis information (from StaticGCT) and a corpus of programs.
func (schema *TargetSchema) BuildGraphChoiceTable(corpus []*Prog, static *StaticGCT, disableDynamic bool) *GraphChoiceTable {
	gct := &GraphChoiceTable{
		prio:        make(GraphPrio),
		resForward:  make([]map[ResourcePath]bool, len(schema.target.Syscalls)),
		resBackward: make([]map[ResourcePath]bool, len(schema.target.Syscalls)),
	}

	for i := range schema.target.Syscalls {
		gct.resForward[i] = make(map[ResourcePath]bool)
		gct.resBackward[i] = make(map[ResourcePath]bool)
	}

	// Dynamic prio is normalized to [graphPrioLowDynamic..graphPrioHigh] range.
	if !disableDynamic {
		a := time.Now()
		fmt.Printf("Computing dynamic prio...\n")
		gct.computeDynamicPrio(corpus, schema)
		b := time.Since(a)
		fmt.Printf("Dynamic prio computed in %v\n", b)
	}

	fmt.Printf("Prio size: %v\n", len(gct.prio))

	// Static prio is normalized to [graphPrioLowStatic..graphPrioHigh] range for entries that are nonzero.
	a := time.Now()
	fmt.Printf("Computing static prio...\n")
	gct.computeStaticPrio(static, schema)
	b := time.Since(a)
	fmt.Printf("Static prio computed in %v\n", b)

	// Disable calls that are not enabled.
	a = time.Now()
	fmt.Printf("Disabling calls...\n")
	for k := range gct.prio {
		if !schema.enabledCalls[k.SyscallA] || !schema.enabledCalls[k.SyscallB] {
			delete(gct.prio, k)
		}
	}
	b = time.Since(a)
	fmt.Printf("Calls disabled in %v\n", b)

	fmt.Printf("Prio size: %v\n", len(gct.prio))

	// Update runsForward and runsBackward.
	a = time.Now()
	fmt.Printf("Updating runs...\n")
	gct.updateRuns(schema)
	b = time.Since(a)
	fmt.Printf("Runs updated in %v\n", b)
	return gct
}

func (gct *GraphChoiceTable) computeStaticPrio(static *StaticGCT, schema *TargetSchema) {
	// Note: entries in the StaticGCT are in range [0..1000000]

	// (GCTForward points from checker to setter, i.e. backwards from the perspective of the graph)
	for syscallB, byArg := range static.GCTForward.ArgRuns {
		if !schema.enabledCalls[syscallB] {
			continue
		}

		for b_idx, entries := range byArg {
			// Static prio specifies top-level paths.
			inB := MakeResourcePath([]int{b_idx})

			for _, entry := range entries {
				syscallA := schema.target.SyscallMap[entry.SetName].ID
				if !schema.enabledCalls[syscallA] {
					continue
				}

				outA := MakeResourcePath([]int{entry.ArgSetIndex})

				if entry.Prob < 100 {
					continue
				}

				// Update prio
				val := (graphPrioLowStatic + (entry.Prob*(graphPrioHigh-graphPrioLowStatic))/1000000)
				prev := gct.getPrio(syscallA, syscallB, outA, inB)
				new_val := prev + val
				gct.setPrio(syscallA, syscallB, outA, inB, new_val)
			}
		}
	}
}

func (gct *GraphChoiceTable) computeDynamicPrio(corpus []*Prog, schema *TargetSchema) {
	maxCount := 0
	for _, p := range corpus {
		g := ProgToGraph(p.Clone())

		for _, n := range g.Nodes {
			syscallA := n.Meta.ID
			for _, out := range n.Outputs {
				if out.NodeIdx < 0 {
					continue
				}

				outA := out.Path

				node_b := out.NodeIdx
				syscallB := g.Nodes[node_b].Meta.ID
				inB := g.Nodes[node_b].Inputs[out.ConnIdx].Path

				p := gct.getPrio(syscallA, syscallB, outA, inB) + 1
				gct.setPrio(syscallA, syscallB, outA, inB, p)

				if p > maxCount {
					maxCount = p
				}
			}
		}
	}

	// Normalize to [graphPrioLowDynamic..graphPrioHigh] range.
	for key := range gct.prio {
		gct.prio[key] = graphPrioLowDynamic + gct.prio[key]*(graphPrioHigh-graphPrioLowDynamic)/maxCount
	}
}

// Sets up the runsForward and runsBackward fields of the GraphChoiceTable based on the internal prio.
func (gct *GraphChoiceTable) updateRuns(schema *TargetSchema) {
	gct.runsBackward = make(map[RunKey][]Entry)
	gct.runsForward = make(map[RunKey][]Entry)

	// Update runsBackward
	for syscallB := range schema.target.Syscalls {
		for inB := range gct.resBackward[syscallB] {
			cumprob := 0
			k := RunKey{syscallB, inB}
			gct.runsBackward[k] = make([]Entry, 0)

			for syscallA := range schema.target.Syscalls {
				for outA := range gct.resForward[syscallA] {
					if w := gct.getPrio(syscallA, syscallB, outA, inB); w > 0 {
						cumprob += w
						gct.runsBackward[k] = append(gct.runsBackward[k], Entry{
							CumProb: cumprob,
							SigIdx:  syscallA,
							Path:    outA,
						})
					}
				}
			}
		}
	}

	// Update runsForward
	for syscallA := range schema.target.Syscalls {
		for outA := range gct.resForward[syscallA] {
			cumprob := 0
			k := RunKey{syscallA, outA}
			gct.runsForward[k] = make([]Entry, 0)

			for syscallB := range schema.target.Syscalls {
				for inB := range gct.resBackward[syscallB] {
					if w := gct.getPrio(syscallA, syscallB, outA, inB); w > 0 {
						cumprob += w
						gct.runsForward[k] = append(gct.runsForward[k], Entry{
							CumProb: cumprob,
							SigIdx:  syscallB,
							Path:    inB,
						})
					}
				}
			}
		}
	}
}

// Sample a predecessor signature for a given signature and input index.
func (gct *GraphChoiceTable) ChoosePred(r *rand.Rand, syscallID int, inputPath ResourcePath) *Entry {
	return choose(r, &gct.runsBackward, syscallID, inputPath)
}

// Sample a successor signature for a given signature and output index.
func (gct *GraphChoiceTable) ChooseSucc(r *rand.Rand, syscallID int, outputPath ResourcePath) *Entry {
	return choose(r, &gct.runsForward, syscallID, outputPath)
}

// Returns the dependency weight between two signatures given their output/input indices.
func (gct *GraphChoiceTable) GetScore(sigA, sigB int, outA, inB ResourcePath) int {
	return gct.getPrio(sigA, sigB, outA, inB)
}

func choose(r *rand.Rand, runs *map[RunKey][]Entry, syscallID int, path ResourcePath) *Entry {
	k := RunKey{syscallID, path}
	if _, ok := (*runs)[k]; !ok {
		return nil
	}

	entries := (*runs)[k]
	if len(entries) == 0 {
		return nil
	}
	rndNum := r.Intn(entries[len(entries)-1].CumProb)
	ind := sort.Search(len(entries), func(i int) bool {
		return entries[i].CumProb >= rndNum
	})
	return &entries[ind]
}

func (g *GraphChoiceTable) DebugPrint() {
	for k, entries := range g.runsForward {
		for _, e := range entries {
			fmt.Printf("%v:%v -> %v:%v: %v\n", k.SyscallID, k.Path, e.SigIdx, e.Path, e.CumProb)
		}
	}
	fmt.Println("=============================")
	for k, entries := range g.runsBackward {
		for _, e := range entries {
			fmt.Printf("%v:%v <- %v:%v: %v\n", k.SyscallID, k.Path, e.SigIdx, e.Path, e.CumProb)
		}
	}
}

func FilterStaticGCT(static *StaticGraphChoiceTable, enabledCalls map[*Syscall]bool, t *Target) *StaticGraphChoiceTable {
	newGCT := &StaticGraphChoiceTable{}
	//newGCT.SyscallRuns = make([][]StaticEntry, len(static.SyscallRuns))
	//newGCT.ResourceRuns = make([]map[string][]StaticEntry, len(static.ResourceRuns))
	newGCT.ArgRuns = make([]map[int][]StaticEntry, len(static.ArgRuns))
	/*
		for i, entry := range static.SyscallRuns {
			if enabledCalls[t.Syscalls[i]] {
				newGCT.SyscallRuns[i] = make([]StaticEntry, 0)
				for _, e := range entry {
					if enabledCalls[t.SyscallMap[e.SetName]] {
						newGCT.SyscallRuns[i] = append(newGCT.SyscallRuns[i], e)
					}
				}
			}
		}

		for i, calls := range static.ResourceRuns {
			if enabledCalls[t.Syscalls[i]] {
				newGCT.ResourceRuns[i] = make(map[string][]StaticEntry)
				for call, entries := range calls {
					if enabledCalls[t.SyscallMap[call]] {
						newGCT.ResourceRuns[i][call] = make([]StaticEntry, 0)
						newGCT.ResourceRuns[i][call] = append(newGCT.ResourceRuns[i][call], entries...)
					}
				}
			}
		}
	*/

	for i, argRuns := range static.ArgRuns {
		if enabledCalls[t.Syscalls[i]] {
			newGCT.ArgRuns[i] = make(map[int][]StaticEntry)
			for argIdx, entries := range argRuns {
				newGCT.ArgRuns[i][argIdx] = make([]StaticEntry, 0)
				for _, e := range entries {
					if enabledCalls[t.SyscallMap[e.SetName]] {
						newGCT.ArgRuns[i][argIdx] = append(newGCT.ArgRuns[i][argIdx], e)
					}
				}
			}
		}
	}
	return newGCT
}
