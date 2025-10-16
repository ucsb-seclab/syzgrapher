package prog

import (
	"fmt"
	"math/rand"
	"sort"
)

const (
	MaxResourcesPerSignature = 32
	MaxSigDepth              = 32
)

type GraphProg struct {
	// needed to reconstruct the Prog
	Target *Target
	Nodes  []*CallNode
	// needed to reconstruct the Prog
	Comments []string
}

type CallNode struct {
	Index int
	// This allows to change the type dynamically depending on the number of resources in structs, arrays, etc.
	Level   int
	Inputs  []NodeRef
	Outputs []NodeRef

	// Forward/Reverse map mirror the structure in SyscallSignature.
	// CallNodes derived from syzkaller programs may not always exist as a signature that we know of so we compute
	// and store this information separately.
	ForwardMap map[int][]int
	ReverseMap map[int][]int

	Context []Arg
	Ret     *ResultArg
	// these fields are needed to reconstruct the Prog
	Meta  *Syscall
	Props CallProps
	// pseudo entpoints have this string set to 'syzgrapher pseudo endpoint', level to maxint, Meta to nil
	Comment string
	// Marker used during graph mutation.
	Marked bool

	// Signature index of this node (unset by default and cached whenever it is queried).
	SigIdx *int
}

// -1 : Resource could have an incoming edge but does not have one (for in); Resource is not used (for out)
// -2 : Resource has been used before, but is not used by any subsequent call = dangling edge (for out), incoming edge missing = dangling edge (for in)
// -3 : This is a special value (for in & out); could be replace with actual resource (for in); could be used (for out)
type NodeRef struct {
	NodeIdx  int
	ConnIdx  int
	Resource *ResultArg
	Path     ResourcePath
}

const (
	// Constants for the 5 possible states of a ResultArg
	SpecialValueDirIn = iota
	NoRefDirIn
	SpecialValueDirOut
	NoRefDirOut
	ExistingRef
	NoRefDirDel
	ExistingRefDel
	SpecialValueDirDel
)

// NOTE: after converting a prog to a graph or a graph to a prog, the source object should not be used anymore

// this function assumes that the Resource are linked up correctly
func GraphToProg(g *GraphProg) *Prog {
	// Sorting by layer is guaranteed to put endpoints with dependencies after the call that produces them
	byLayer := make([]*CallNode, 0)
	numPseudo := 0
	for _, n := range g.Nodes {
		if n.Comment == "syzgrapher pseudo endpoint" {
			res := n.Context[0].(*ResultArg)
			delete(res.Res.uses, res)
			numPseudo++
			continue
		}
		byLayer = append(byLayer, n)
	}

	// Sort by layer (primary) and index (secondary).
	sort.Slice(byLayer, func(i, j int) bool {
		if byLayer[i].Level == byLayer[j].Level {
			return byLayer[i].Index < byLayer[j].Index
		}
		return byLayer[i].Level < byLayer[j].Level
	})

	p := &Prog{
		Target:   g.Target,
		Calls:    make([]*Call, len(g.Nodes)-numPseudo),
		Comments: make([]string, len(g.Comments)),
	}
	copy(p.Comments, g.Comments)

	// create all calls
	for i, n := range byLayer {
		p.Calls[i] = &Call{
			Meta:    n.Meta,
			Args:    n.Context,
			Ret:     n.Ret,
			Props:   n.Props,
			Comment: n.Comment,
		}
	}

	return p
}

func ProgToGraph(p *Prog) *GraphProg {
	graph := &GraphProg{
		Target:   p.Target,
		Nodes:    make([]*CallNode, len(p.Calls)),
		Comments: make([]string, len(p.Comments)),
	}
	copy(graph.Comments, p.Comments)

	// create all nodes, fill with basic information
	for i, c := range p.Calls {
		graph.Nodes[i] = &CallNode{
			Index:      i,
			Level:      i,
			Inputs:     make([]NodeRef, 0),
			Outputs:    make([]NodeRef, 0),
			ForwardMap: make(map[int][]int),
			ReverseMap: make(map[int][]int),
			Context:    c.Args,
			Ret:        c.Ret,
			Meta:       c.Meta,
			Props:      c.Props,
			Comment:    c.Comment,
			Marked:     false,
		}
		if len(c.Meta.Args) != len(c.Args) {
			ser := p.Serialize()
			text := string(ser[:])
			fmt.Printf("serialized prog: %s\n", text)
			panic("number of arguments does not match: " + fmt.Sprintf("%+v: %+v", c.Meta, c.Args))
		}
	}

	// fill Inputs and Outputs arrays with correct refs
	// this pretends as if every in resource is always inout
	for _, n := range graph.Nodes {
		n.Inputs = make([]NodeRef, 0)
		n.Outputs = make([]NodeRef, 0)
	}

	lastUsed := make(map[*ResultArg]NodeRef)
	expUses := make(map[*ResultArg]int)
	for i, n := range graph.Nodes {
		ForeachArgGraph(n, func(arg Arg, isRet bool, path ResourcePath) {
			if isRet {
				ref := NodeRef{
					NodeIdx: i,
					ConnIdx: len(n.Outputs),
					Path:    path,
				}
				lastUsed[n.Ret] = ref
				expUses[n.Ret] = len(n.Ret.uses)

				if len(n.Ret.uses) == 0 {
					// not used, dangling edge
					n.Outputs = append(n.Outputs, NodeRef{-1, -1, n.Ret, path})
				} else {
					// not used so far, will be changed when we find the use
					n.Outputs = append(n.Outputs, NodeRef{-2, -2, n.Ret, path})
				}
				n.ReverseMap[len(n.Outputs)-1] = make([]int, 0)
				n.ForwardMap[-1] = append(n.ForwardMap[-1], len(n.Outputs)-1)
			} else {
				inputIndexes := make([]int, 0)
				outputIndexes := make([]int, 0)
				if resArg, ok := arg.(*ResultArg); ok {
					if resArg.Res == nil {
						// this is a new resource
						ref := NodeRef{
							NodeIdx: i,
							ConnIdx: len(n.Outputs),
							Path:    path,
						}
						lastUsed[resArg] = ref
						expUses[resArg] = len(resArg.uses)

						specialValue := false
						if resArg.GetDir() == DirIn || resArg.GetDir() == DirDel {
							specialValue = isSpecialValue(resArg)
							if specialValue {
								n.Inputs = append(n.Inputs, NodeRef{-3, -3, resArg, path})
							} else {
								n.Inputs = append(n.Inputs, NodeRef{-1, -1, resArg, path})
							}
							inputIndexes = append(inputIndexes, len(n.Inputs)-1)
						}
						if len(resArg.uses) == 0 {
							if specialValue {
								n.Outputs = append(n.Outputs, NodeRef{-3, -3, resArg, path})
								outputIndexes = append(outputIndexes, len(n.Outputs)-1)
							} else if resArg.GetDir() != DirDel {
								// not used, dangling edge
								n.Outputs = append(n.Outputs, NodeRef{-1, -1, resArg, path})
								outputIndexes = append(outputIndexes, len(n.Outputs)-1)
							}
						} else {
							// not used so far, will be changed when we find the use
							n.Outputs = append(n.Outputs, NodeRef{-2, -2, resArg, path})
							outputIndexes = append(outputIndexes, len(n.Outputs)-1)
						}
					} else {
						// this is a use of a resource
						ref, ok := lastUsed[resArg.Res]
						if !ok {
							panic("resource not found")
						}
						expUses[resArg.Res] = expUses[resArg.Res] - 1

						ref.Resource = resArg
						n.Inputs = append(n.Inputs, ref)
						inputIndexes = append(inputIndexes, len(n.Inputs)-1)
						graph.Nodes[ref.NodeIdx].Outputs[ref.ConnIdx].NodeIdx = i
						graph.Nodes[ref.NodeIdx].Outputs[ref.ConnIdx].ConnIdx = len(n.Inputs) - 1
						lastUsed[resArg.Res] = NodeRef{i, len(n.Outputs), nil, path}
						if !(expUses[resArg.Res] == 0 && resArg.GetDir() == DirDel) {
							n.Outputs = append(n.Outputs, NodeRef{-2, -2, resArg, path})
							outputIndexes = append(outputIndexes, len(n.Outputs)-1)
						}

						if len(resArg.uses) != 0 {
							lastUsed[resArg] = NodeRef{i, len(n.Outputs), nil, path}
							resArg.out = true
							n.Outputs = append(n.Outputs, NodeRef{-2, -2, resArg, path})
							outputIndexes = append(outputIndexes, len(n.Outputs)-1)
						}
					}
				}
				if len(inputIndexes) != 0 && len(outputIndexes) != 0 {
					for _, i := range inputIndexes {
						n.ForwardMap[i] = outputIndexes
					}
					for _, i := range outputIndexes {
						n.ReverseMap[i] = inputIndexes
					}
				} else if len(inputIndexes) != 0 {
					n.ReverseMap[-1] = append(n.ReverseMap[-1], inputIndexes...)
				} else if len(outputIndexes) != 0 {
					n.ForwardMap[-1] = append(n.ForwardMap[-1], outputIndexes...)
				}
			}
		})
	}

	// graph.Sanitize()

	return graph
}

// Cleans up the graph by:
// - adding pseudo endpoints for dangling edges
// - normalizing min level to zero
func (g *GraphProg) Sanitize() {
	for i := 0; i < len(g.Nodes); i++ {
		addPseudoEndpoints(g, i)
	}

	// Shift the minimum level to zero.
	// If we don't do this, after many mutations we can hit integer overflow and things break...
	minLevel := 0
	for _, n := range g.Nodes {
		if n.Level < minLevel {
			minLevel = n.Level
		}
	}
	for _, n := range g.Nodes {
		n.Level -= minLevel
	}
}

// TODO: perhaps track this dynamically instead of recomputing it every time
func (g *GraphProg) NumRealNodes() int {
	nodes := 0
	for _, n := range g.Nodes {
		if n.Comment != "syzgrapher pseudo endpoint" {
			nodes++
		}
	}
	return nodes
}

func addPseudoEndpoints(p *GraphProg, call int) {
	n := p.Nodes[call]
	if len(n.Outputs) == 0 {
		return
	}
	for i, ref := range n.Outputs {
		if ref.ConnIdx != -2 && ref.ConnIdx != -1 {
			continue
		}

		// find the resource
		resArg := ref.Resource

		// add the pseudo endpoint
		psRef := NodeRef{
			NodeIdx: call,
			ConnIdx: i,
		}

		var psRes *ResultArg
		if resArg.Res == nil {
			psRes = MakeResultArg(resArg.Type(), DirIn, resArg, 0)
		} else {
			psRes = MakeResultArg(resArg.Type(), DirIn, resArg.Res, 0)
		}

		psRef.Resource = psRes
		n.Outputs[i].NodeIdx = len(p.Nodes)
		n.Outputs[i].ConnIdx = 0
		pseudo := &CallNode{
			Index:   len(p.Nodes),
			Level:   n.Level + 1,
			Inputs:  []NodeRef{psRef},
			Outputs: make([]NodeRef, 0),
			Context: []Arg{psRes},
			Ret:     nil,
			Meta:    nil,
			Comment: "syzgrapher pseudo endpoint",
			Marked:  false,
		}

		p.Nodes = append(p.Nodes, pseudo)
	}
}

func ForeachArgGraph(node *CallNode, fn func(Arg, bool, ResourcePath)) {
	for idx, a := range node.Context {
		foreachArgGraphImpl(a, fn, false, []int{idx})
	}

	if node.Ret != nil {
		foreachArgGraphImpl(node.Ret, fn, true, []int{len(node.Context)})
	}
}

func foreachArgGraphImpl(arg Arg, fn func(Arg, bool, ResourcePath), isRet bool, path []int) {
	fn(arg, isRet, MakeResourcePath(path))
	switch a := arg.(type) {
	case *PointerArg:
		if a.Res != nil {
			foreachArgGraphImpl(a.Res, fn, isRet, append(path, 0))
		}
	case *UnionArg:
		foreachArgGraphImpl(a.Option, fn, isRet, append(path, a.Index))
	case *GroupArg:
		for idx, inner := range a.Inner {
			foreachArgGraphImpl(inner, fn, isRet, append(path, idx))
		}
	}
}

// graph version of analyze(). Node with index idx is the last node to be analyzed
func analyzeGraph(ct *ChoiceTable, corpus []*Prog, g *GraphProg, idx int) *state {
	s := newState(g.Target, ct, corpus)
	if len(g.Nodes) == 0 {
		return s
	}

	// walk graph backwards from idx to all roots
	nodes_to_visit := make([]int, 0)
	nodes_to_visit = append(nodes_to_visit, idx)

	seen := make(map[int]bool)
	seen[idx] = true

	next := 0

	for next < len(nodes_to_visit) {
		node_idx := nodes_to_visit[next]
		next++
		for _, ref := range g.Nodes[node_idx].Inputs {
			if ref.NodeIdx < 0 {
				// this is a dangling edge
				continue
			}
			if seen[ref.NodeIdx] {
				continue
			}
			seen[ref.NodeIdx] = true
			nodes_to_visit = append(nodes_to_visit, ref.NodeIdx)
		}
	}

	others := make([]int, 0)
	for i := 0; i < len(g.Nodes); i++ {
		if !seen[i] {
			others = append(others, i)
		}
	}

	// handle these nodes in reverse order of visiting
	for i := len(nodes_to_visit) - 1; i >= 0; i-- {
		node_idx := nodes_to_visit[i]
		node := g.Nodes[node_idx]
		if node.Comment == "syzgrapher pseudo endpoint" {
			continue
		}
		s.analyzeNode(node, true)
	}

	// for all other nodes, ignore resources but still analyze them
	for _, node_idx := range others {
		node := g.Nodes[node_idx]
		if node.Comment == "syzgrapher pseudo endpoint" {
			continue
		}
		s.analyzeNode(node, false)
	}

	return s
}

func (s *state) analyzeNode(node *CallNode, resources bool) {
	// TODO
	sw := &stateWrapper{s: s, resources: resources}
	ForeachArgGraph(node, sw.analyzeArgGraph)
}

func (sw *stateWrapper) analyzeArgGraph(arg Arg, _ bool, _ ResourcePath) {
	sw.s.analyzeArgsImpl(arg, nil, sw.resources)
}

func isSpecialValue(resArg *ResultArg) bool {
	specialValue := false
	vs := resArg.Type().(*ResourceType).SpecialValues()
	for _, val := range vs {
		if val == resArg.Val {
			specialValue = true
			break
		}
	}
	return specialValue
}

func determineState(resArg *ResultArg) int {
	if resArg.Res == nil {
		specialValue := false
		if resArg.GetDir() == DirIn || resArg.GetDir() == DirDel {
			specialValue = isSpecialValue(resArg)
			if specialValue {
				if resArg.GetDir() == DirDel {
					return SpecialValueDirDel
				}
				return SpecialValueDirIn
			} else {
				if resArg.GetDir() == DirDel {
					return NoRefDirDel
				}
				return NoRefDirIn
			}
		}
		if specialValue {
			return SpecialValueDirOut
		} else {
			return NoRefDirOut
		}
	} else {
		if resArg.GetDir() == DirDel {
			return ExistingRefDel
		}
		return ExistingRef
	}
}

func cloneArg(arg Arg) Arg {
	var arg1 Arg
	switch a := arg.(type) {
	case *ConstArg:
		a1 := new(ConstArg)
		*a1 = *a
		arg1 = a1
	case *PointerArg:
		a1 := new(PointerArg)
		*a1 = *a
		arg1 = a1
		if a.Res != nil {
			a1.Res = cloneArg(a.Res)
		}
	case *DataArg:
		a1 := new(DataArg)
		*a1 = *a
		a1.Dat = append([]byte{}, a.Dat...)
		arg1 = a1
	case *GroupArg:
		a1 := new(GroupArg)
		*a1 = *a
		arg1 = a1
		a1.Inner = make([]Arg, len(a.Inner))
		for i, inner := range a.Inner {
			a1.Inner[i] = cloneArg(inner)
		}
	case *UnionArg:
		a1 := new(UnionArg)
		*a1 = *a
		arg1 = a1
		a1.Option = cloneArg(a.Option)
	case *ResultArg:
		a1 := new(ResultArg)
		*a1 = *a
		arg1 = a1
		a1.uses = nil
		if len(a.uses) != 0 {
			a.out = true
			a1.out = true
		}
	default:
		panic(fmt.Sprintf("unknown arg type %T", arg))
	}
	return arg1
}

// type ResourceID struct {
// 	Name         string
// 	SpecialValue bool
// }

// Represents a single variant of a (potentially variadic) syscall.
//
// The signature should also contain enough information to describe how the arguments
// are formed. E.g. structure/list information.
// type SyscallSignature struct {
// 	SyscallID int
// 	Inputs    []ResourceID
// 	Outputs   []ResourceID

// 	// Forward and Reverse map describe the relationship between the inputs and outputs.
// 	//
// 	// An input of type T at index i should have the same type as the output(s) at index ForwardMap[i].
// 	// Similarly, an output of type T at index i should have the same type as the input(s) at index ReverseMap[i].
// 	//
// 	// Additionally ForwardMap[-1] stores all outputs that have no matching inputs and ReverseMap[-1] stores all
// 	// inputs that have no matching outputs.
// 	ForwardMap map[int][]int
// 	ReverseMap map[int][]int

// 	// maps index from GCT to index in Inputs/Outputs
// 	GCT2Inputs  map[int]int
// 	GCT2Outputs map[int]int

// 	// also context?
// 	Context []Arg
// 	Ret     *ResultArg
// 	Props   CallProps
// 	Comment string
// }

type ResourcePath = [MaxSigDepth]int

func MakeResourcePath(path []int) ResourcePath {
	var p [MaxSigDepth]int
	copy(p[:], path)
	if len(path) < MaxSigDepth {
		p[len(path)] = -1
	}
	return p
}

func SliceResourcePath(path ResourcePath) []int {
	for i, v := range path {
		if v == -1 {
			return path[:i]
		}
	}
	return path[:]
}

func SubstituteResourcePath(path ResourcePath, idx int, val int) ResourcePath {
	var p [MaxSigDepth]int
	copy(p[:], path[:])
	p[idx] = val
	return p
}

type ResourceRef struct {
	Name string
	Path ResourcePath
}

func MakeResourceRef(name string, path []int) ResourceRef {
	return ResourceRef{
		Name: name,
		Path: MakeResourcePath(path),
	}
}

type ResourceInfo struct {
	Name string
	Dir  Dir
	Path ResourcePath
}

func MakeResourceInfo(name string, dir Dir, path []int) ResourceInfo {
	return ResourceInfo{
		Name: name,
		Dir:  dir,
		Path: MakeResourcePath(path),
	}
}

type SyscallTemplate struct {
	SyscallID int
	Inputs    []ResourceRef
	Outputs   []ResourceRef
	Resources []ResourceInfo

	// Args root will be a SampleGuideStruct or SampleGuideFree
	Args []SampleGuide

	// Metadata about resource linkage
	ForwardMap map[int][]int
	ReverseMap map[int][]int
}

func indent(depth int) string {
	out := ""
	for i := 0; i < depth; i++ {
		out += " "
	}
	return out
}

type SampleGuide interface {
	DebugPrint(depth int)
}

type SampleGuideFree struct{}

func (s SampleGuideFree) DebugPrint(depth int) {
	fmt.Printf("%sFree\n", indent(depth))
}

// Indicates that the child type can be freely generated but may generate resources.
// These resources are not tracked by the signature and should be reset to special values.
type SampleGuideFreeReset struct{}

func (s SampleGuideFreeReset) DebugPrint(depth int) {
	fmt.Printf("%sFreeReset\n", indent(depth))
}

type SampleGuideResource struct {
	Name string
	Dir  Dir
}

func (s SampleGuideResource) DebugPrint(depth int) {
	fmt.Printf("%sResource %s %v\n", indent(depth), s.Name, s.Dir)
}

type SampleGuideStruct struct {
	Fields []SampleGuide
}

func (s SampleGuideStruct) DebugPrint(depth int) {
	fmt.Printf("%sStruct\n", indent(depth))
	for i, f := range s.Fields {
		fmt.Printf("%sField %d\n", indent(depth+1), i)
		f.DebugPrint(depth + 2)
	}
}

type SampleGuidePtr struct {
	Elem SampleGuide
}

func (s SampleGuidePtr) DebugPrint(depth int) {
	fmt.Printf("%sPtr\n", indent(depth))
	s.Elem.DebugPrint(depth + 1)
}

// Fixed union choice
type SampleGuideUnion struct {
	Option int
	Elem   SampleGuide
}

func (s SampleGuideUnion) DebugPrint(depth int) {
	fmt.Printf("%sUnion\n", indent(depth))
	fmt.Printf("%sOption %d\n", indent(depth+1), s.Option)
	s.Elem.DebugPrint(depth + 2)
}

// Fixed array size
type SampleGuideArray struct {
	Length int
	Elem   SampleGuide
}

func (s SampleGuideArray) DebugPrint(depth int) {
	fmt.Printf("%sArray\n", indent(depth))
	fmt.Printf("%sLength %d\n", indent(depth+1), s.Length)
	s.Elem.DebugPrint(depth + 1)
}

// Fixed optional choice
type SampleGuideOptional struct {
	Enabled bool
	Elem    SampleGuide
}

func (s SampleGuideOptional) DebugPrint(depth int) {
	fmt.Printf("%sOptional\n", indent(depth))
	fmt.Printf("%sEnabled %v\n", indent(depth+1), s.Enabled)
	s.Elem.DebugPrint(depth + 1)
}

// func (sig *SyscallSignature) DebugPrint() {
// 	fmt.Printf("Signature for syscall %d\n", sig.SyscallID)
// 	fmt.Printf("Inputs:\n")
// 	for i, in := range sig.Inputs {
// 		fmt.Printf("\t%d: %s (special: %v)\n", i, in.Name, in.SpecialValue)
// 	}
// 	fmt.Printf("Outputs:\n")
// 	for i, out := range sig.Outputs {
// 		fmt.Printf("\t%d: %s (special: %v)\n", i, out.Name, out.SpecialValue)
// 	}
// }

func (t *SyscallTemplate) DebugPrint() {
	fmt.Printf("Template for syscall %d\n", t.SyscallID)
	fmt.Printf("Inputs:\n")
	for i, in := range t.Inputs {
		fmt.Printf("\t%d: %s\n", i, in.Name)
	}
	fmt.Printf("Outputs:\n")
	for i, out := range t.Outputs {
		fmt.Printf("\t%d: %s\n", i, out.Name)
	}
	fmt.Printf("Resources:\n")
	for i, r := range t.Resources {
		fmt.Printf("\t%d: %s %v %v\n", i, r.Name, r.Dir, SliceResourcePath(r.Path))
	}
	for i, a := range t.Args {
		fmt.Printf("Arg %d:\n", i)
		a.DebugPrint(1)
	}
}

func (s *Syscall) Sample(t *Target) (templates []SyscallTemplate, ok bool) {
	// fmt.Printf("Sampling syscall %v\n", s.Name)

	if s.Attrs.NoGenerate {
		return nil, false
	}

	// These are currently too big to handle
	invalid := []string{
		"ioctl$IOCTL_CONFIG_SYS_RESOURCE_PARAMETERS",
		"ioctl$IOCTL_START_ACCEL_DEV",
		"ioctl$IOCTL_STOP_ACCEL_DEV",
	}

	for _, i := range invalid {
		if s.Name == i {
			return nil, false
		}
	}

	args, ok := sampleTypeFields(s.Args, []int{}, DirIn, 0)
	if !ok {
		return nil, false
	}
	ret, ok := sampleType(s.Ret, []int{len(s.Args)}, DirOut, 0)
	if !ok {
		return nil, false
	}

	// fmt.Printf("Args: %v\n", args)
	// fmt.Printf("Ret: %v\n", ret)

	if len(ret) != 1 {
		panic("expected exactly one return value type")
	}

	out := make([]SyscallTemplate, 0)

	if len(args) == 0 {
		g := make([]SampleGuide, 0)
		for range s.Args {
			g = append(g, &SampleGuideFree{})
		}
		t := SyscallTemplate{
			SyscallID: s.ID,
			Args:      g,
			Outputs:   ret[0].Outputs,
			Resources: ret[0].Resources,
		}
		t.BuildMap()
		out = append(out, t)
	} else {
		for _, a := range args {
			outputs := make([]ResourceRef, 0)
			outputs = append(outputs, a.Outputs...)
			outputs = append(outputs, ret[0].Outputs...)

			resources := make([]ResourceInfo, 0)
			resources = append(resources, a.Resources...)
			resources = append(resources, ret[0].Resources...)

			var args []SampleGuide
			if v, ok := a.Guide.(*SampleGuideStruct); ok {
				args = v.Fields
			} else {
				panic("expected struct")
			}

			t := SyscallTemplate{
				SyscallID: s.ID,
				Args:      args,
				Inputs:    a.Inputs,
				Outputs:   outputs,
				Resources: resources,
			}
			t.BuildMap()
			out = append(out, t)
		}
	}

	return out, true
}

func (t *SyscallTemplate) BuildMap() {
	t.ForwardMap = make(map[int][]int)
	t.ReverseMap = make(map[int][]int)

	in_idx := 0
	out_idx := 0

	for _, r := range t.Resources {
		switch r.Dir {
		case DirIn:
			t.ForwardMap[in_idx] = []int{out_idx}
			t.ReverseMap[out_idx] = []int{in_idx}
			in_idx += 1
			out_idx += 1
		case DirOut:
			t.ForwardMap[-1] = append(t.ForwardMap[-1], out_idx)
			out_idx += 1
		case DirInOut:
			t.ForwardMap[in_idx] = []int{out_idx, out_idx + 1}
			t.ReverseMap[out_idx] = []int{in_idx}
			t.ReverseMap[out_idx+1] = []int{in_idx}
			in_idx += 1
			out_idx += 2
		case DirDel:
			t.ReverseMap[-1] = append(t.ReverseMap[-1], in_idx)
			in_idx += 1
		}
	}
}

type PartialSample struct {
	Guide     SampleGuide
	Inputs    []ResourceRef
	Outputs   []ResourceRef
	Resources []ResourceInfo
}

func sampleType(t Type, path []int, dir Dir, depth int) (samples []PartialSample, ok bool) {
	if t == nil || depth > MaxSigDepth {
		return []PartialSample{
			{
				Guide: &SampleGuideFree{},
			},
		}, true
	}

	inner, ok := sampleTypeInner(t, path, dir, depth)
	if !ok {
		return nil, false
	}

	if t.Optional() {
		out := make([]PartialSample, 0)
		for _, p := range inner {
			out = append(out, PartialSample{
				Guide:     &SampleGuideOptional{Enabled: true, Elem: p.Guide},
				Inputs:    p.Inputs,
				Outputs:   p.Outputs,
				Resources: p.Resources,
			})
		}
		out = append(out, PartialSample{
			Guide: &SampleGuideOptional{Enabled: false, Elem: &SampleGuideFree{}},
		})
		return out, true
	} else {
		return inner, true
	}
}

func sampleTypeInner(t Type, path []int, dir Dir, depth int) (samples []PartialSample, ok bool) {
	switch a := t.(type) {
	case *ResourceType:
		// fmt.Printf("%v: ResourceType: %v\n", path, a)
		switch dir {
		case DirIn: // in-out
			return []PartialSample{
				{
					Guide: &SampleGuideResource{
						Name: a.Name(),
						Dir:  dir,
					},
					Inputs:    []ResourceRef{MakeResourceRef(a.Name(), path)},
					Outputs:   []ResourceRef{MakeResourceRef(a.Name(), path)},
					Resources: []ResourceInfo{MakeResourceInfo(a.Name(), dir, path)},
				},
			}, true
		case DirOut: // out
			return []PartialSample{
				{
					Guide: &SampleGuideResource{
						Name: a.Name(),
						Dir:  dir,
					},
					Outputs:   []ResourceRef{MakeResourceRef(a.Name(), path)},
					Resources: []ResourceInfo{MakeResourceInfo(a.Name(), dir, path)},
				},
			}, true
		case DirInOut: // in-out + out
			return []PartialSample{
				{
					Guide: &SampleGuideResource{
						Name: a.Name(),
						Dir:  DirInOut,
					},
					Inputs: []ResourceRef{MakeResourceRef(a.Name(), path)},
					Outputs: []ResourceRef{
						MakeResourceRef(a.Name(), path),
						MakeResourceRef(a.Name(), path),
					},
					Resources: []ResourceInfo{MakeResourceInfo(a.Name(), DirInOut, path)},
				},
			}, true
		case DirDel: // in
			return []PartialSample{
				{
					Guide: &SampleGuideResource{
						Name: a.Name(),
						Dir:  dir,
					},
					Inputs:    []ResourceRef{MakeResourceRef(a.Name(), path)},
					Resources: []ResourceInfo{MakeResourceInfo(a.Name(), dir, path)},
				},
			}, true
		default:
			panic("unknown dir")
		}
	case *ArrayType:
		// fmt.Printf("%v: ArrayType: %v\n", path, a)
		samples, ok := sampleType(a.Elem, append(path, 0), dir, depth+1)
		if !ok {
			return nil, false
		}
		if len(samples) == 0 {
			// No child resources, so this is free to be any length.
			return []PartialSample{}, true
		} else {
			// Check if this is a direct array of resources
			if _, ok := a.Elem.(*ResourceType); ok {
				out := make([]PartialSample, 0)

				// The provided samples will contain paths with index 0 for this array index.
				// When we generate variants, we need to replace the array index with the correct values.

				var min_size int
				var max_size int
				switch a.Kind {
				case ArrayRandLen:
					min_size = 0
					max_size = 5
				case ArrayRangeLen:
					min_size = int(a.RangeBegin)
					max_size = int(a.RangeEnd)
					if max_size > 5 {
						max_size = 5
					}
				}

				// Iterate over fixed lengths
				for size := min_size; size <= max_size; size += 1 {
					for _, p := range samples {
						inputs := make([]ResourceRef, 0)
						outputs := make([]ResourceRef, 0)
						resources := make([]ResourceInfo, 0)

						for i := 0; i < size; i++ {
							for _, in := range p.Inputs {
								inputs = append(inputs, ResourceRef{
									Name: in.Name,
									Path: SubstituteResourcePath(in.Path, len(path), i),
								})
							}
							for _, out := range p.Outputs {
								outputs = append(outputs, ResourceRef{
									Name: out.Name,
									Path: SubstituteResourcePath(out.Path, len(path), i),
								})
							}
							for _, r := range p.Resources {
								resources = append(resources, ResourceInfo{
									Name: r.Name,
									Dir:  r.Dir,
									Path: SubstituteResourcePath(r.Path, len(path), i),
								})
							}
						}

						out = append(out, PartialSample{
							Guide:     &SampleGuideArray{Length: size, Elem: p.Guide},
							Inputs:    inputs,
							Outputs:   outputs,
							Resources: resources,
						})
					}
				}

				return out, true
			} else {
				return []PartialSample{
					{
						Guide: &SampleGuideFreeReset{},
					},
				}, true
			}
		}
	case *StructType:
		// fmt.Printf("%v: StructType: %v\n", path, a)
		return sampleTypeFields(a.Fields, path, dir, depth+1)
	case *UnionType:
		// fmt.Printf("%v: UnionType: %v\n", path, a)

		has_distinction := false
		partials := make([][]PartialSample, 0)

		for idx, f := range a.Fields {
			partial, ok := sampleType(f.Type, append(path, idx), f.Dir(dir), depth+1)
			if !ok {
				return nil, false
			}
			partials = append(partials, partial)

			if len(partial) > 0 {
				has_distinction = true
			}
		}

		if !has_distinction {
			return []PartialSample{}, true
		} else {
			out := make([]PartialSample, 0)

			// Iterate over each option and return specialized guides.
			for idx, partial := range partials {
				if len(partial) == 0 {
					// No child resources
					out = append(out, PartialSample{
						Guide: &SampleGuideUnion{Option: idx, Elem: &SampleGuideFree{}},
					})
				} else {
					for _, p := range partial {
						out = append(out, PartialSample{
							Guide:     &SampleGuideUnion{Option: idx, Elem: p.Guide},
							Inputs:    p.Inputs,
							Outputs:   p.Outputs,
							Resources: p.Resources,
						})
					}
				}
			}

			return out, true
		}
	case *PtrType:
		// fmt.Printf("%v: PtrType: %v\n", path, a)
		partial, ok := sampleType(a.Elem, append(path, 0), a.ElemDir, depth+1)
		if !ok {
			return nil, false
		}
		if len(partial) == 0 {
			// No child resources
			return []PartialSample{}, true
		} else {
			out := make([]PartialSample, 0)

			for _, p := range partial {
				out = append(out, PartialSample{
					Guide:     &SampleGuidePtr{Elem: p.Guide},
					Inputs:    p.Inputs,
					Outputs:   p.Outputs,
					Resources: p.Resources,
				})
			}

			return out, true
		}
	default:
		// fmt.Printf("%v: Other type: %v\n", path, a)
		return []PartialSample{}, true
	}
}

// This logic is shared between syscall and struct
func sampleTypeFields(fields []Field, path []int, dir Dir, depth int) (samples []PartialSample, ok bool) {
	has_distinction := false
	partials := make([][]PartialSample, 0)

	for idx, f := range fields {
		partial, ok := sampleType(f.Type, append(path, idx), f.Dir(dir), depth+1)
		if !ok {
			return nil, false
		}
		partials = append(partials, partial)

		if len(partial) > 0 {
			has_distinction = true
		}
	}

	if !has_distinction {
		return []PartialSample{}, true
	} else {
		// count number of pairwise combinations
		num := 1
		for _, p := range partials {
			if len(p) > 0 {
				num *= len(p)
			}
			// fmt.Printf("p: %v\n", p)
		}
		// fmt.Printf("Num: %v\n", num)

		out := make([]PartialSample, 0)

		for x := 0; x < num; x++ {
			z := x
			inputs := make([]ResourceRef, 0)
			outputs := make([]ResourceRef, 0)
			resources := make([]ResourceInfo, 0)
			guide := &SampleGuideStruct{Fields: make([]SampleGuide, len(partials))}

			for idx, p := range partials {
				if len(p) == 0 {
					// No child resources
					guide.Fields[idx] = &SampleGuideFree{}
				} else {
					pick := z % len(p)
					z /= len(p)

					inputs = append(inputs, p[pick].Inputs...)
					outputs = append(outputs, p[pick].Outputs...)
					resources = append(resources, p[pick].Resources...)
					guide.Fields[idx] = p[pick].Guide
				}
			}

			out = append(out, PartialSample{
				Guide:     guide,
				Inputs:    inputs,
				Outputs:   outputs,
				Resources: resources,
			})
		}

		return out, true
	}
}

// Returns a list of all possible syscall signatures.
//
// TODO: how to handle syscalls with potentially infinite variants. Perhaps we could
// set a bound or sample a handful randomly?
// func (s *Syscall) SampleSignatures(t *Target) []*SyscallSignature {
// 	/*
// 	 for syscalls that have a set signature, this should be simple:
// 	 ask syzkaller to generate an instance, find inputs/outputs and initialize
// 	 the interface in SyscallSignature

// 	 for syscalls that have a variadic signature, this is more complicated:
// 	 we first generate one random signature through syzkaller. Then, we traverse
// 	 all args. Whenever we find a Union, we clone the program and generate one new
// 	 version for every possible option. Whenever we find an array, we clone the program
// 	 and generate two additional versions with other randomly chosen lengths.

// 	 After generating multiple instances per system call, we need to verify that
// 	 the signature is actually different.
// 	*/

// 	// Some syscalls cannot be generated by syzkaller
// 	if s.Attrs.NoGenerate {
// 		return nil
// 	}

// 	signatures := make([]*SyscallSignature, 0)
// 	// generate an instance of this system call using syzkaller
// 	cs := s.genSignatureArgInstances(t)

// 	// extract the inputs/outputs from the args
// 	for _, c := range cs {
// 		sig := &SyscallSignature{
// 			SyscallID:   s.ID,
// 			Inputs:      make([]ResourceID, 0),
// 			Outputs:     make([]ResourceID, 0),
// 			ForwardMap:  make(map[int][]int),
// 			ReverseMap:  make(map[int][]int),
// 			GCT2Inputs:  make(map[int]int),
// 			GCT2Outputs: make(map[int]int),
// 			Context:     c.Args,
// 			Ret:         c.Ret,
// 			Props:       c.Props,
// 			Comment:     c.Comment,
// 		}

// 		extractSignature(sig, c)
// 		for i := range sig.Inputs {
// 			sig.Inputs[i].SpecialValue = false
// 		}
// 		for i := range sig.Outputs {
// 			sig.Outputs[i].SpecialValue = false
// 		}

// 		// check whether signature is new or not
// 		if isNewSignature(sig, signatures) {
// 			signatures = append(signatures, sig)
// 		}
// 	}

// 	return signatures
// }

// func signaturesEqual(s1, s2 *SyscallSignature) bool {
// 	if len(s1.Inputs) != len(s2.Inputs) {
// 		return false
// 	}
// 	if len(s1.Outputs) != len(s2.Outputs) {
// 		return false
// 	}
// 	for i := range s1.Inputs {
// 		if s1.Inputs[i].Name != s2.Inputs[i].Name {
// 			return false
// 		}
// 		if s1.Inputs[i].SpecialValue != s2.Inputs[i].SpecialValue {
// 			return false
// 		}
// 	}
// 	for i := range s1.Outputs {
// 		if s1.Outputs[i].Name != s2.Outputs[i].Name {
// 			return false
// 		}
// 		if s1.Outputs[i].SpecialValue != s2.Outputs[i].SpecialValue {
// 			return false
// 		}
// 	}

// 	return true
// }

// func isNewSignature(sig *SyscallSignature, signatures []*SyscallSignature) bool {
// 	for _, s := range signatures {
// 		if signaturesEqual(sig, s) {
// 			return false
// 		}
// 	}
// 	return true
// }

// func extractSignature(sig *SyscallSignature, c *Call) {
// 	for i, a := range c.Args {
// 		ForeachSubArg(a, func(arg Arg, _ *ArgCtx) {
// 			inputIndexes := make([]int, 0)
// 			outputIndexes := make([]int, 0)
// 			if res, ok := arg.(*ResultArg); ok {
// 				if res.Res == nil {
// 					specialValue := false
// 					if res.GetDir() == DirIn || res.GetDir() == DirDel {
// 						specialValue = isSpecialValue(res)
// 						sig.Inputs = append(sig.Inputs, ResourceID{res.Type().Name(), specialValue})
// 						inputIndexes = append(inputIndexes, len(sig.Inputs)-1)
// 						if a == arg {
// 							sig.GCT2Inputs[i] = len(sig.Inputs) - 1
// 						}
// 					}
// 					if res.GetDir() == DirIn || res.GetDir() == DirOut || res.GetDir() == DirInOut {
// 						sig.Outputs = append(sig.Outputs, ResourceID{res.Type().Name(), specialValue})
// 						outputIndexes = append(outputIndexes, len(sig.Outputs)-1)
// 						if a == arg {
// 							sig.GCT2Outputs[i] = len(sig.Outputs) - 1
// 						}
// 					}
// 				} else {
// 					if res.GetDir() == DirIn || res.GetDir() == DirDel || res.GetDir() == DirInOut {
// 						sig.Inputs = append(sig.Inputs, ResourceID{res.Type().Name(), false})
// 						inputIndexes = append(inputIndexes, len(sig.Inputs)-1)
// 						if a == arg {
// 							sig.GCT2Inputs[i] = len(sig.Inputs) - 1
// 						}
// 					}
// 					if res.GetDir() == DirIn || res.GetDir() == DirOut || res.GetDir() == DirInOut {
// 						sig.Outputs = append(sig.Outputs, ResourceID{res.Type().Name(), false})
// 						outputIndexes = append(outputIndexes, len(sig.Outputs)-1)
// 						if a == arg {
// 							sig.GCT2Outputs[i] = len(sig.Outputs) - 1
// 						}
// 					}
// 					if res.out {
// 						sig.Outputs = append(sig.Outputs, ResourceID{res.Type().Name(), false})
// 						outputIndexes = append(outputIndexes, len(sig.Outputs)-1)
// 					}
// 				}
// 			}
// 			if len(inputIndexes) != 0 && len(outputIndexes) != 0 {
// 				for _, i := range inputIndexes {
// 					sig.ForwardMap[i] = outputIndexes
// 				}
// 				for _, i := range outputIndexes {
// 					sig.ReverseMap[i] = inputIndexes
// 				}
// 			} else if len(inputIndexes) != 0 {
// 				sig.ReverseMap[-1] = append(sig.ReverseMap[-1], inputIndexes...)
// 			} else if len(outputIndexes) != 0 {
// 				sig.ForwardMap[-1] = append(sig.ForwardMap[-1], outputIndexes...)
// 			}
// 		})
// 	}

// 	if c.Ret != nil {
// 		sig.Outputs = append(sig.Outputs, ResourceID{c.Ret.Type().Name(), false})
// 		sig.ReverseMap[len(sig.Outputs)-1] = make([]int, 0)
// 		sig.ForwardMap[-1] = append(sig.ForwardMap[-1], len(sig.Outputs)-1)
// 		sig.GCT2Outputs[len(c.Args)] = len(sig.Outputs) - 1
// 	}
// }

func (s *Syscall) genSignatureArgInstances(t *Target) []*Call {
	state := newState(t, t.DefaultChoiceTable(), nil)
	r := newRand(t, rand.NewSource(0))
	c := MakeCall(s, nil)
	var calls []*Call
	c.Args, calls = r.generateArgs(state, s.Args, DirIn)
	r.target.assignSizesCall(c)
	// TODO should we call s.analyze(c)??

	// generate additional variants
	p := &Prog{
		Target: t,
		Calls:  append(calls, c),
	}

	var clones []*Prog = []*Prog{}
	for i := range c.Args {
		clones = append(clones, traverseAndClone(p, c.Args[i], []int{i}, r)...)
	}

	sigs := make([]*Call, 0)
	sigs = append(sigs, c)
	for _, cl := range clones {
		sigs = append(sigs, cl.Calls[len(cl.Calls)-1])
	}

	return sigs
}

// Traverses the whole argument tree. Whenever it finds a UnionArg, it will generate a new
// program with the exact same structure but with a different option selected. It will
// generate a program for each option.
// Whenever it finds a GroupArg that represents an array, it will generate a new program with
// the exact same structure but with a different length. It will generate two new programs.
func traverseAndClone(p *Prog, arg Arg, path []int, r *randGen) []*Prog {
	fmt.Printf("traverseAndClone: %v -> (%v) (opt: %v) %+v\n", path, arg.Type(), arg.Type().Optional(), arg)

	clones := make([]*Prog, 0)
	switch a := arg.(type) {
	case *PointerArg:
		if a.Res != nil {
			return traverseAndClone(p, a.Res, path, r)
		}
	case *UnionArg:
		// generate programs with all other options
		for i := range a.Type().(*UnionType).Fields {
			if i == a.Index {
				continue
			}
			cl := p.Clone()
			findAndReplace(cl, path, i, r)
			r.target.assignSizesCall(cl.Calls[len(cl.Calls)-1])
			clones = append(clones, cl)
		}
		newPath := make([]int, len(path))
		copy(newPath, path)
		clones = append(clones, traverseAndClone(p, a.Option, append(newPath, a.Index), r)...)
	case *GroupArg:
		// generate programs with other lengths if this is an array
		if arrT, ok := a.Type().(*ArrayType); ok {
			low, high := 0, 10
			span := 11
			if arrT.Kind == ArrayRangeLen {
				low = int(arrT.RangeBegin)
				high = int(arrT.RangeEnd)
				span = high - low + 1
			}
			firstval := -1
			for i := 0; i < 2; i++ {
				// get rand value within the bounds. if it's not new, increase with modulo
				rVal := r.Intn(span)
				orig := rVal
				done := false
				for rVal+low == firstval || rVal+low == len(a.Inner) {
					rVal = (rVal + 1) % span
					if rVal == orig%span {
						done = true
						break
					}
				}
				if done {
					break
				}
				firstval = rVal + low
				cl := p.Clone()
				findAndReplace(cl, path, rVal+low, r)
				r.target.assignSizesCall(cl.Calls[len(cl.Calls)-1])
				clones = append(clones, cl)
			}
		}
		for i := range a.Inner {
			newPath := make([]int, len(path))
			copy(newPath, path)
			clones = append(clones, traverseAndClone(p, a.Inner[i], append(newPath, i), r)...)
		}
	case *ResultArg:
		fmt.Printf("ResultArg: %v\n", a.GetDir())
		break
		if a.GetDir() == DirInOut {
			cl := p.Clone()
			findAndReplace(cl, path, 0, r)
			r.target.assignSizesCall(cl.Calls[len(cl.Calls)-1])
			clones = append(clones, cl)
		}
	}
	return clones
}

// Finds the argument at the given path and replaces it with an argument according to the provided value.
func findAndReplace(p *Prog, path []int, index int, r *randGen) {
	cur := p.Calls[len(p.Calls)-1].Args[path[0]]
	i := 1
	for true {
		switch a := cur.(type) {
		case *PointerArg:
			if a.Res != nil {
				cur = a.Res
			}
		case *UnionArg:
			if i == len(path) {
				a.Index = index
				optType := a.Type().(*UnionType).Fields[index].Type
				optDir := a.Type().(*UnionType).Fields[index].Dir(a.GetDir())
				state := analyze(p.Target.DefaultChoiceTable(), nil, p, nil)
				opt, calls := r.generateArg(state, optType, optDir)
				a.Option = opt
				if calls != nil {
					p.Calls = append(calls, p.Calls...)
				}
				return
			}
			cur = a.Option
			i++
		case *GroupArg:
			if i == len(path) {
				if _, ok := a.Type().(*ArrayType); !ok {
					panic("Expected array, got struct")
				}
				if index < len(a.Inner) {
					a.Inner = a.Inner[:index]
				} else {
					for len(a.Inner) < index {
						state := analyze(p.Target.DefaultChoiceTable(), nil, p, nil)
						at := a.Type().(*ArrayType)
						arg, calls := r.generateArg(state, at.Elem, a.GetDir())
						a.Inner = append(a.Inner, arg)
						if calls != nil {
							p.Calls = append(calls, p.Calls...)
						}
					}
				}
				return
			}
			cur = a.Inner[path[i]]
			i++
		case *ResultArg:
			// Flip the state of an inout Resource: if it generated the resource
			// before, then it should now expect a previously generated resource
			// and vice versa.
			if a.GetDir() != DirInOut {
				panic("Expected in-out result argument")
			}
			st := determineState(a)
			if st == NoRefDirOut {
				// NOTE: this is super hacky. The idea is that, since
				// a.Res is not null anymore, this will be seen as input
				// and output. The self-reference might trigger issues if
				// this Resource will not later be linked to some other
				// Resource through Link().
				a.Res = a
				a.uses[a] = true
				a.out = true
			} else if st == ExistingRef {
				delete(a.Res.uses, a)
				a.Res = nil
				a.out = false
			} else {
				panic("Unexpected state")
			}
		default:
			break
		}
	}
	panic("Didn't find the argument at the given path")
}

func (node *CallNode) findByPath(path ResourcePath) *ResultArg {
	p := SliceResourcePath(path)
	root := p[0]
	var cur Arg
	if root < len(node.Context) {
		cur = node.Context[root]
	} else {
		cur = node.Ret
	}

	idx := 1
	for idx < len(p) {
		switch a := cur.(type) {
		case *PointerArg:
			cur = a.Res
		case *UnionArg:
			cur = a.Option
			if p[idx] != a.Index {
				panic("Unexpected index")
			}
		case *GroupArg:
			cur = a.Inner[p[idx]]
		case *ResultArg:
			if idx != len(p)-1 {
				panic("Unexpected index")
			}
			return a
		default:
			panic("Unexpected arg type")
		}
		idx++
	}

	if res, ok := cur.(*ResultArg); ok {
		return res
	}

	fmt.Printf("didn't find the argument at the given path, curr: %+v", cur)
	panic("Didn't find the argument at the given path")
}

func CreateFromTemplate(template *SyscallTemplate, level int, t *Target, rand *rand.Rand, state *state, verbose bool) *CallNode {
	if verbose {
		fmt.Printf("Creating call from template %v (%v)\n", template.SyscallID, t.Syscalls[template.SyscallID].Name)
		template.DebugPrint()
	}

	meta := t.Syscalls[template.SyscallID]
	call := &CallNode{
		Level:      level,
		Inputs:     make([]NodeRef, len(template.Inputs)),
		Outputs:    make([]NodeRef, len(template.Outputs)),
		ForwardMap: template.ForwardMap,
		ReverseMap: template.ReverseMap,
		Context:    make([]Arg, len(meta.Args)),
		Ret:        MakeReturnArg(meta.Ret),
		Meta:       meta,
		Props:      CallProps{},
		Comment:    "",
		Marked:     false,
	}

	//state := newState(t, t.DefaultChoiceTable(), nil)
	r := newRandExisting(t, rand)
	for idx, arg := range template.Args {
		call.Context[idx], _ = createArgGuided(arg, meta.Args[idx].Type, meta.Args[idx].Dir(DirIn), t, state, r, verbose, []int{idx})
	}

	t.assignSizesArray(call.Context, meta.Args, nil)

	inp := 0
	out := 0

	for _, rinfo := range template.Resources {
		// fmt.Printf("Resource: %v\n", rinfo)
		res := call.findByPath(rinfo.Path)

		switch res.Dir {
		case DirIn:
			call.Inputs[inp].NodeIdx = -1
			call.Inputs[inp].ConnIdx = -1
			call.Inputs[inp].Resource = res
			call.Inputs[inp].Path = rinfo.Path
			inp++
			call.Outputs[out].NodeIdx = -1
			call.Outputs[out].ConnIdx = -1
			call.Outputs[out].Resource = res
			call.Outputs[out].Path = rinfo.Path
			out++
		case DirOut:
			call.Outputs[out].NodeIdx = -1
			call.Outputs[out].ConnIdx = -1
			call.Outputs[out].Resource = res
			call.Outputs[out].Path = rinfo.Path
			out++
		case DirInOut:
			call.Inputs[inp].NodeIdx = -1
			call.Inputs[inp].ConnIdx = -1
			call.Inputs[inp].Resource = res
			call.Inputs[inp].Path = rinfo.Path
			inp++
			call.Outputs[out].NodeIdx = -1
			call.Outputs[out].ConnIdx = -1
			call.Outputs[out].Resource = res
			call.Outputs[out].Path = rinfo.Path
			out++
			call.Outputs[out].NodeIdx = -1
			call.Outputs[out].ConnIdx = -1
			call.Outputs[out].Resource = res
			call.Outputs[out].Path = rinfo.Path
			res.out = true
			out++
		case DirDel:
			call.Inputs[inp].NodeIdx = -1
			call.Inputs[inp].ConnIdx = -1
			call.Inputs[inp].Resource = res
			call.Inputs[inp].Path = rinfo.Path
			inp++
		}
	}

	if inp != len(call.Inputs) {
		fmt.Printf("inp: %d, len(call.Inputs): %d\n", inp, len(call.Inputs))
		panic("Did not find the right number of input resources")
	}
	if out != len(call.Outputs) {
		fmt.Printf("out: %d, len(call.Outputs): %d\n", out, len(call.Outputs))
		panic("Did not find the right number of output resources")
	}

	return call
}

func createArgGuided(guide SampleGuide, t Type, dir Dir, target *Target, s *state, r *randGen, verbose bool, path []int) (arg Arg, calls []*Call) {
	if a, ok := guide.(*SampleGuideOptional); ok {
		if a.Enabled {
			return createArgGuidedInner(a.Elem, t, dir, target, s, r, verbose, path)
		} else {
			if _, ok := t.(*ResourceType); ok {
				arg = MakeResultArg(t, dir, nil, 0)
			} else {
				arg = t.DefaultArg(dir)
			}
			return
		}
	} else {
		return createArgGuidedInner(guide, t, dir, target, s, r, verbose, path)
	}
}

func createArgGuidedInner(guide SampleGuide, t Type, dir Dir, target *Target, s *state, r *randGen, verbose bool, path []int) (arg Arg, calls []*Call) {
	if verbose {
		fmt.Printf("Sampling %v with guide %v\n", path, guide)
	}

	switch a := guide.(type) {
	case *SampleGuideFree:
		// Invoke syzkaller code to generate a random argument
		// This is guaranteed not to have any resources
		arg, calls = r.generateArg(s, t, DirIn)
	case *SampleGuideFreeReset:
		// Invoke syzkaller code to generate a random argument
		// We will need to reset any generated resources to special values
		arg, _ = r.generateArg(s, t, DirIn)
		resetResources(&arg)
	case *SampleGuideResource:
		arg = MakeResultArg(t, dir, nil, 0)
	case *SampleGuideStruct:
		var tv *StructType
		if vv, ok := t.(*StructType); !ok {
			panic("Expected struct type")
		} else {
			tv = vv
		}

		inner := make([]Arg, len(a.Fields))
		for i, f := range a.Fields {
			inner[i], calls = createArgGuided(f, tv.Fields[i].Type, tv.Fields[i].Dir(dir), target, s, r, verbose, append(path, i))
		}
		arg = MakeGroupArg(t, dir, inner)
	case *SampleGuidePtr:
		var tv *PtrType
		if vv, ok := t.(*PtrType); !ok {
			panic("Expected ptr type")
		} else {
			tv = vv
		}

		inner, _ := createArgGuided(a.Elem, tv.Elem, tv.ElemDir, target, s, r, verbose, append(path, 0))
		arg = r.allocAddr(s, t, dir, inner.Size(), inner)
	case *SampleGuideUnion:
		var tv *UnionType
		if vv, ok := t.(*UnionType); !ok {
			panic("Expected union type")
		} else {
			tv = vv
		}

		opt, _ := createArgGuided(a.Elem, tv.Fields[a.Option].Type, tv.Fields[a.Option].Dir(dir), target, s, r, verbose, append(path, 0))
		arg = MakeUnionArg(t, dir, opt, a.Option)
	case *SampleGuideArray:
		var tv *ArrayType
		if vv, ok := t.(*ArrayType); !ok {
			panic("Expected array type")
		} else {
			tv = vv
		}

		inner := make([]Arg, a.Length)
		for i := 0; i < a.Length; i++ {
			inner[i], calls = createArgGuided(a.Elem, tv.Elem, dir, target, s, r, verbose, append(path, i))
		}

		arg = MakeGroupArg(t, dir, inner)
	default:
		// print the type
		fmt.Printf("Type: %T\n", guide)
		fmt.Printf("Guide: %v\n", guide)
		panic("Unknown guide type")
	}
	if len(calls) != 0 {
		fmt.Printf("Expected no calls, got %v\n", len(calls))
		guide.DebugPrint(0)

		for _, c := range calls {
			fmt.Printf("Call: %v\n", c)
		}

		panic("Expected no calls")
	}
	return
}

func resetResources(arg *Arg) {
	switch a := (*arg).(type) {
	case *GroupArg:
		for i := range a.Inner {
			resetResources(&a.Inner[i])
		}
	case *UnionArg:
		resetResources(&a.Option)
	case *PointerArg:
		if a.Res != nil {
			resetResources(&a.Res)
		}
	case *ResultArg:
		a.Val = 0
		a.Res = nil
		a.uses = make(map[*ResultArg]bool)
	}
}

// Creates a new CallNode for the given signature. Incoming/outgoing edges are not set.
// func CreateCallNode(signature *SyscallSignature, level int, t *Target) *CallNode {
// 	call := &CallNode{
// 		Level:   level,
// 		Inputs:  make([]NodeRef, len(signature.Inputs)),
// 		Outputs: make([]NodeRef, len(signature.Outputs)),
// 		Context: make([]Arg, len(signature.Context)),
// 		Ret:     signature.Ret,
// 		Meta:    t.Syscalls[signature.SyscallID],
// 		Props:   signature.Props,
// 		Comment: signature.Comment,
// 		Marked:  false,
// 	}

// 	for i := range signature.Inputs {
// 		call.Inputs[i].NodeIdx = -1
// 		call.Inputs[i].ConnIdx = -1
// 	}
// 	for i := range signature.Outputs {
// 		call.Outputs[i].NodeIdx = -1
// 		call.Outputs[i].ConnIdx = -1
// 	}

// 	for i := range signature.Context {
// 		call.Context[i] = cloneArg(signature.Context[i])
// 	}

// 	if call.Ret != nil {
// 		call.Ret = cloneArg(signature.Ret).(*ResultArg)
// 	}

// 	// find resources and add to noderefs
// 	inp := 0
// 	out := 0
// 	ForeachArgGraph(call, func(arg Arg, isRet bool) {
// 		if resArg, ok := arg.(*ResultArg); ok {
// 			if isRet {
// 				call.Outputs[out].NodeIdx = -1
// 				call.Outputs[out].ConnIdx = -1
// 				call.Outputs[out].Resource = resArg
// 				out++
// 			} else {
// 				inval := -10
// 				outval := -10
// 				switch determineState(resArg) {
// 				case SpecialValueDirIn:
// 					inval = -3
// 					outval = -3
// 				case NoRefDirIn:
// 					inval = -1
// 					outval = -1
// 				case SpecialValueDirOut:
// 					outval = -3
// 				case NoRefDirOut:
// 					outval = -1
// 				case ExistingRef:
// 					inval = -1
// 					outval = -1
// 					resArg.Res = nil
// 					resArg.uses = make(map[*ResultArg]bool)
// 					// inouts that refer to another resource and have an output themselves
// 					// require two output edges.
// 					if resArg.out {
// 						call.Outputs[out].NodeIdx = outval
// 						call.Outputs[out].ConnIdx = outval
// 						call.Outputs[out].Resource = resArg
// 						out++
// 					}
// 				case NoRefDirDel:
// 					inval = -1
// 				case ExistingRefDel:
// 					inval = -1
// 					resArg.Res = nil
// 					resArg.uses = make(map[*ResultArg]bool)
// 				case SpecialValueDirDel:
// 					inval = -3
// 				}
// 				if inval != -10 {
// 					call.Inputs[inp].NodeIdx = inval
// 					call.Inputs[inp].ConnIdx = inval
// 					call.Inputs[inp].Resource = resArg
// 					inp++
// 				}
// 				if outval != -10 {
// 					call.Outputs[out].NodeIdx = outval
// 					call.Outputs[out].ConnIdx = outval
// 					call.Outputs[out].Resource = resArg
// 					out++
// 				}

// 			}
// 		}
// 	})

// 	if inp != len(call.Inputs) {
// 		fmt.Printf("inp: %d, len(call.Inputs): %d\n", inp, len(call.Inputs))
// 		panic("Did not find the right number of input resources")
// 	}
// 	if out != len(call.Outputs) {
// 		fmt.Printf("out: %d, len(call.Outputs): %d\n", out, len(call.Outputs))
// 		panic("Did not find the right number of output resources")
// 	}

// 	return call
// }

// Adds a new CallNode to the graph. Returns the new node's index.
func (g *GraphProg) AddCallNode(n *CallNode) int {
	idx := len(g.Nodes)
	g.Nodes = append(g.Nodes, n)
	n.Index = idx
	return idx
}

// Link two nodes in the graph.
//
// [node_a]output(conn_a) ----> (conn_b)input[node_b]
func (g *GraphProg) Link(node_b, conn_b, node_a, conn_a int) {
	// set up graph edges
	a := g.Nodes[node_a]
	a.Inputs[conn_a].NodeIdx = node_b
	a.Inputs[conn_a].ConnIdx = conn_b

	b := g.Nodes[node_b]
	b.Outputs[conn_b].NodeIdx = node_a
	b.Outputs[conn_b].ConnIdx = conn_a

	// add links between resources
	var res_a, res_b *ResultArg
	res_a = a.Inputs[conn_a].Resource
	res_b = b.Outputs[conn_b].Resource

	// it this resource is responsible for two links, we need to check that
	// the intention is indeed to link to this resource and not its reference
	if (res_b.out && conn_b > 0 && b.Outputs[conn_b-1].Resource == res_b) ||
		res_b.GetDir() == DirOut || res_b.Res == nil {
		//res_a.Res = res_b
		//res_b.uses[res_a] = true
		if res_b.uses == nil {
			res_b.uses = make(map[*ResultArg]bool)
		}
	} else {
		res_b = res_b.Res
		//res_a.Res = res_b.Res
		//res_b.Res.uses[res_a] = true
	}
	if res_a.Res != nil {
		delete(res_a.Res.uses, res_a)
	}
	res_a.Res = res_b
	res_b.uses[res_a] = true

	/*
		if res_a.GetDir() == DirInOut && res_a.out {
			return
		}
	*/

	// if this resource is not consumed by node_a and other nodes are using it, those also need to be linked to res_b
	cur_node := node_a
	cur_conn := conn_a
	for true {
		node := g.Nodes[cur_node]
		// find output edge with the same resource
		out_conn := -1
		for i := range node.Outputs {
			if node.Outputs[i].Resource == node.Inputs[cur_conn].Resource {
				out_conn = i
				break
			}
		}
		if out_conn == -1 {
			break
		}

		if node.Outputs[out_conn].NodeIdx < 0 {
			break
		}

		// follow the edge and link the resources
		next_node := g.Nodes[node.Outputs[out_conn].NodeIdx]
		next_res := next_node.Inputs[node.Outputs[out_conn].ConnIdx].Resource
		if next_res.Res != nil {
			delete(next_res.Res.uses, next_res)
		}
		next_res.Res = res_b
		res_b.uses[next_res] = true

		cur_node = node.Outputs[out_conn].NodeIdx
		cur_conn = node.Outputs[out_conn].ConnIdx
	}
}

func (g *GraphProg) Unlink(node_a, conn_a int) {
	node_b := g.Nodes[node_a].Outputs[conn_a].NodeIdx
	conn_b := g.Nodes[node_a].Outputs[conn_a].ConnIdx
	g.unlink(node_a, conn_a, node_b, conn_b)
}

func (g *GraphProg) UnlinkBackward(node_b, conn_b int) {
	node_a := g.Nodes[node_b].Inputs[conn_b].NodeIdx
	conn_a := g.Nodes[node_b].Inputs[conn_b].ConnIdx
	g.unlink(node_a, conn_a, node_b, conn_b)
}

// Unlink a node/conn from its forward connection.
//
// [node_a]output(conn_a) --X-> (conn_b)input[node_b]
func (g *GraphProg) unlink(node_b, conn_b, node_a, conn_a int) {
	// remove edge
	a := g.Nodes[node_a]
	a.Inputs[conn_a].NodeIdx = -2
	a.Inputs[conn_a].ConnIdx = -2

	b := g.Nodes[node_b]
	b.Outputs[conn_b].NodeIdx = -2
	b.Outputs[conn_b].ConnIdx = -2

	// unlink resources
	var res_a, res_b *ResultArg
	res_a = a.Inputs[conn_a].Resource
	res_b = b.Outputs[conn_b].Resource

	if res_a.Res == res_b {
		delete(res_b.uses, res_a)
		if len(res_b.uses) == 0 {
			b.Outputs[conn_b].NodeIdx = -1
			b.Outputs[conn_b].ConnIdx = -1
		}
	} else if res_b.Res != nil && res_a.Res == res_b.Res {
		delete(res_b.Res.uses, res_a)
		res_b = res_b.Res
	} else {
		panic("something is wrong with the links between resources")
	}
	res_a.Res = nil

	/*
		if res_a.GetDir() == DirInOut && res_a.out {
			return
		}
	*/
	// if this resource is not consumed by node_a and other nodes are using it, those also need to be unlinked from res_b
	cur_node := node_a
	cur_conn := conn_a
	for true {
		node := g.Nodes[cur_node]
		// find output edge with the same resource
		out_conn := -1
		for i := range node.Outputs {
			if node.Outputs[i].Resource == node.Inputs[cur_conn].Resource {
				out_conn = i
				break
			}
		}
		if out_conn == -1 {
			break
		}

		// If we hit a dangling edge, stop tracing.
		if node.Outputs[out_conn].NodeIdx < 0 {
			break
		}

		// follow the edge and link the resources
		next_node := g.Nodes[node.Outputs[out_conn].NodeIdx]
		next_res := next_node.Inputs[node.Outputs[out_conn].ConnIdx].Resource
		_, ok := node.Inputs[cur_conn].Resource.uses[next_res]
		if next_res.Res == node.Inputs[cur_conn].Resource && ok {
			// there is no actual outgoing edge rom the original resource, it ends here. this is a new resource
			// TODO check if this is still required after porting all the patches from mainline,
			// cause I am surprised that this is happening at all
			break
		}
		if next_res.Res != res_b {
			panic("links between resources are broken")
		}
		delete(res_b.uses, next_res)
		next_res.Res = res_a
		if res_a.uses == nil {
			res_a.uses = make(map[*ResultArg]bool)
		}
		res_a.uses[next_res] = true

		cur_node = node.Outputs[out_conn].NodeIdx
		cur_conn = node.Outputs[out_conn].ConnIdx
	}
}

// Extract the signature from a given CallNode and try to find a matching signature in the schema.
//
// If found returns the index of the matching signature, otherwise -1.
// func (n *CallNode) FindMatchingSignature(schema *TargetSchema) int {
// 	if n.SigIdx != nil {
// 		return *n.SigIdx
// 	}

// 	call := &Call{
// 		Meta:    n.Meta,
// 		Args:    n.Context,
// 		Ret:     n.Ret,
// 		Props:   n.Props,
// 		Comment: n.Comment,
// 	}

// 	sig := &SyscallSignature{
// 		SyscallID:   n.Meta.ID,
// 		Inputs:      make([]ResourceID, 0),
// 		Outputs:     make([]ResourceID, 0),
// 		ForwardMap:  make(map[int][]int),
// 		ReverseMap:  make(map[int][]int),
// 		GCT2Inputs:  make(map[int]int),
// 		GCT2Outputs: make(map[int]int),
// 		Context:     n.Context,
// 		Ret:         n.Ret,
// 		Props:       n.Props,
// 		Comment:     n.Comment,
// 	}

// 	extractSignature(sig, call)

// 	idx := -1
// 	for i, s := range schema.Signatures {
// 		if signaturesEqual(sig, &s) {
// 			idx = i
// 			break
// 		}
// 	}

// 	// Cache the result.
// 	n.SigIdx = &idx
// 	return idx
// }
