package prog

import (
	"fmt"
	"math/rand"
	"sort"

	"github.com/google/syzkaller/pkg/log"
)

const (
	MutationSpliceIn = iota
	MutationSpliceOut
	MutationCrosslink
	MutationCrossover
	MutationPriority
	MutationIsolateGraph
	MutationReplaceConstructor
	MutationWrappedMutateArg
	MutationInsertNode
	MutationInPlace

	MutationCount
)

const MaxMutationSteps = 4

type TargetSchema struct {
	target *Target

	MaxDepth int

	// A list of many sampled syscall signatures. This list is immutable although certain signatures may be
	// disabled at runtime.
	Signatures          []SyscallTemplate
	SignaturesBySyscall map[int][]int

	// Syscalls that we couldn't generate signatures for
	InvalidSyscalls map[int]bool

	// Maps (syscall, res_path) to a list of syscall templates for the syscall that contain the specified resource.
	SignatureProducers map[RunKey][]int
	SignatureConsumers map[RunKey][]int

	ResourceNodes map[ResourceNodeRef]*ResourceNode

	// A mapping of resource to all signatures that use this resource. At runtime, this is updated to filter
	// out invalid syscalls.
	Users        map[string][]*ResourceUser
	EnabledUsers map[string][]int

	enabledCalls map[int]bool

	// List of enabled signature indexes
	enabledSignatures []int
}

// A resource tree consists of an alternating ResourceTree/SigTree structure and describes
// all of the ways to construct a given resource through some sequence of syscalls.
type ResourceNode struct {
	// A resource tree is disabled if all of the SigTree children are disabled.
	Enabled bool

	// If true, this resource should be filled with a special value instead of an edge.
	SpecialValue bool

	// This resource tree describes how to construct "at least X" for a given resource X.
	MinRes string

	// All the possible ways to construct this resource.
	Children        []SigNode
	EnabledChildren []int
}

type ResourceNodeRef struct {
	// Max depth specifies the maximum number of syscalls that can be used to construct this resource.
	// E.g. specifying 0 requires the children of this node take no other inputs.
	// Specifying 1 allows the children to take inputs of depth 0.
	// etc...
	MaxDepth int
	MinRes   string
}

type SigNode struct {
	// A SigTree is disabled if any of the input resource trees is disabled or the syscall is disabled.
	Enabled bool

	// This parameter describes which one of the outputs in the signature corresponds to the
	// resource described by the parent ResourceTree.
	OutResourceIdx int

	// Index in TargetSchema.Signatures
	SigIdx int

	// Reference to the base syscall. Note that multiple SigTree's may share the same syscall.
	SyscallID int

	// Resources that we need to construct as inputs to invoke this syscall.
	Inputs []ResourceNodeRef
}

// Represents a signature that uses and consumes some resource x.
// sig[SigIdx] takes resource x at InputIdx and produces it at OutputIdx.
type ResourceUser struct {
	// Disabled if the syscall is disabled or we cannot construct the other required resources.
	Enabled   bool
	SigIdx    int
	SyscallID int

	InputPath  ResourcePath
	OutputPath ResourcePath
	InputIdx   int
	OutputIdx  int
}

// Represents a pointer to a missing edge in the graph.
type EdgeRef struct {
	// For missing inputs, this represents the minimum required resource (e.g. >= X).
	// For free outputs, this represents an exact resource (e.g. == X).
	Resource string
	NodeIdx  int
	ConnIdx  int
	Input    bool
	Level    int

	// This starts at the schema's max depth and is decremented as we complete the graph.
	// Unused for free outputs.
	MaxDepth int
}

type EdgeList struct {
	Edges []EdgeRef
}

func (e *EdgeList) push(edge EdgeRef) {
	e.Edges = append(e.Edges, edge)
}

func (e *EdgeList) pop() EdgeRef {
	ref, edges := e.Edges[0], e.Edges[1:]
	e.Edges = edges
	return ref
}

func (e *EdgeList) size() int {
	return len(e.Edges)
}

func (e *EdgeList) remove(idx int) {
	sz := len(e.Edges)
	e.Edges[idx], e.Edges[sz-1] = e.Edges[sz-1], e.Edges[idx]
	e.Edges = e.Edges[:sz-1]
}

type GraphMutationContext struct {
	TargetSchema *TargetSchema
	Rand         *rand.Rand
	Verbose      bool
	MaxNodes     int

	// Graph choice table (disabled if nil).
	GCT *GraphChoiceTable

	// What percentage of the time do we attempt to reuse existing resources instead of generating new syscalls.
	FreqReuse float32

	// For mutation history tracking.
	History *OriginMutatedGraph

	// Need to curry these parameters in case we want to invoke syzkaller-default mutators.
	CT       *ChoiceTable
	NoMutate map[int]bool
	Corpus   []*Prog
}

func (ctx *GraphMutationContext) Logf(format string, args ...interface{}) {
	if ctx.Verbose {
		fmt.Printf(format, args...)
	}
}

func (schema *TargetSchema) SetTarget(t *Target) {
	schema.target = t
}

func (schema *TargetSchema) Target() *Target {
	return schema.target
}

func (s *TargetSchema) IsConstructable(name string) bool {
	ref := ResourceNodeRef{
		MaxDepth: s.MaxDepth,
		MinRes:   name,
	}
	if node, ok := s.ResourceNodes[ref]; ok {
		return node.Enabled && len(node.Children) > 0
	}
	return false
}

func (s *TargetSchema) GetConstructor(name string, max_depth int) *ResourceNode {
	ref := ResourceNodeRef{
		MaxDepth: max_depth,
		MinRes:   name,
	}
	if node, ok := s.ResourceNodes[ref]; ok {
		return node
	}
	return nil
}

func (s *TargetSchema) GetMinConstructor(name string) *ResourceNode {
	for depth := 0; depth <= s.MaxDepth; depth++ {
		ref := ResourceNodeRef{depth, name}
		if node, ok := s.ResourceNodes[ref]; ok {
			if node.Enabled {
				return node
			}
		}
	}
	return nil
}

// Returns true if a is more specific or equal to b.
func (s *TargetSchema) isMoreSpecificOrEq(a, b string) bool {
	k1 := s.target.resourceMap[a].Kind
	k2 := s.target.resourceMap[b].Kind

	if len(k1) < len(k2) {
		return false
	}

	for i, kind := range k2 {
		if kind != k1[i] {
			return false
		}
	}

	return true
}

// Returns true if a > b.
func (s *TargetSchema) isMoreGeneral(a, b string) bool {
	k1 := s.target.resourceMap[a].Kind
	k2 := s.target.resourceMap[b].Kind

	if len(k1) >= len(k2) {
		return false
	}

	for i, kind := range k1 {
		if kind != k2[i] {
			return false
		}
	}

	return true
}

func (s *TargetSchema) PrintEnabled() {
	log.Logf(0, "Enabled signatures (%v):\n", len(s.enabledSignatures))
	for _, idx := range s.enabledSignatures {
		log.Logf(0, " - %v\n", s.Signatures[idx])
	}

	log.Logf(0, "Constructable resources:\n")
	for _, r := range s.target.Resources {
		if s.IsConstructable(r.Name) {
			log.Logf(0, " - %v\n", r.Name)
		}
	}
}

func (s *TargetSchema) ApplySyscallFilter(enabledCalls map[int]bool) {
	s.enabledCalls = enabledCalls

	// The resource nod structure is a DAG so we can apply the filter in reverse topological order.
	for depth := s.MaxDepth; depth >= 0; depth-- {
		for _, r := range s.target.Resources {
			ref := ResourceNodeRef{depth, r.Name}
			if node, ok := s.ResourceNodes[ref]; ok {
				s.applySyscallFilterResourceNode(node)
			}
		}
	}

	for rname, users := range s.Users {
		s.EnabledUsers[rname] = make([]int, 0)
		for user_idx, user := range users {
			if !enabledCalls[user.SyscallID] {
				user.Enabled = false
			} else {
				// Ensure we can construct the other required resources with the current filter.
				user.Enabled = true
				sig := s.Signatures[user.SigIdx]

				for _, in := range sig.Inputs {
					if in.Path != user.InputPath {
						// Check if we can construct this resource.
						if !s.IsConstructable(in.Name) {
							user.Enabled = false
							break
						}
					}
				}

				if user.Enabled {
					s.EnabledUsers[rname] = append(s.EnabledUsers[rname], user_idx)
				}
			}
		}
	}

	s.enabledSignatures = make([]int, 0)
	for sig_idx, sig := range s.Signatures {
		call := s.target.Syscalls[sig.SyscallID]
		if call.Attrs.NoGenerate {
			continue
		}
		if enabledCalls[sig.SyscallID] {
			s.enabledSignatures = append(s.enabledSignatures, sig_idx)
		}
	}
}

func (s *TargetSchema) applySyscallFilterResourceNode(r *ResourceNode) {
	r.Enabled = false
	r.EnabledChildren = make([]int, 0)
	for sig_idx, sig_node := range r.Children {
		s.applySyscallFilterSigNode(&sig_node)
		if sig_node.Enabled {
			r.Enabled = true
			r.EnabledChildren = append(r.EnabledChildren, sig_idx)
		}
	}
}

func (s *TargetSchema) applySyscallFilterSigNode(n *SigNode) {
	n.Enabled = true
	if !s.enabledCalls[n.SyscallID] {
		n.Enabled = false
		return
	}

	for _, ref := range n.Inputs {
		if node, ok := s.ResourceNodes[ref]; ok {
			if !node.Enabled {
				n.Enabled = false
				return
			}
		} else {
			panic("Missing resource node")
		}
	}
}

func (t *Target) ComputeBaseSchema() *TargetSchema {
	// TODO: configurable parameters
	max_depth := 3

	// Build a list of all syscall signatures.
	signatures := make([]SyscallTemplate, 0)
	invalid := make(map[int]bool)
	for _, c := range t.Syscalls {
		templates, ok := c.Sample(t)
		if !ok {
			fmt.Printf("No templates for syscall: %v - %v\n", c.ID, c.Name)
			invalid[c.ID] = true
		} else {
			signatures = append(signatures, templates...)
		}
	}

	by_syscall := make(map[int][]int)
	signature_producers := make(map[RunKey][]int)
	signature_consumers := make(map[RunKey][]int)

	for i, sig := range signatures {
		by_syscall[sig.SyscallID] = append(by_syscall[sig.SyscallID], i)

		for _, in := range sig.Inputs {
			key := RunKey{sig.SyscallID, in.Path}
			signature_consumers[key] = append(signature_consumers[key], i)
		}

		for _, out := range sig.Outputs {
			key := RunKey{sig.SyscallID, out.Path}
			signature_producers[key] = append(signature_producers[key], i)
		}
	}

	s := TargetSchema{
		target:              t,
		MaxDepth:            max_depth,
		Signatures:          signatures,
		SignaturesBySyscall: by_syscall,
		InvalidSyscalls:     invalid,
		SignatureProducers:  signature_producers,
		SignatureConsumers:  signature_consumers,
		ResourceNodes:       make(map[ResourceNodeRef]*ResourceNode),
		Users:               make(map[string][]*ResourceUser),
		EnabledUsers:        make(map[string][]int),
		enabledCalls:        nil,
	}

	// Compute constructors for resources.
	for _, r := range t.Resources {
		t.BuildResourceNode(&s, r.Name, max_depth)

		s.Users[r.Name] = make([]*ResourceUser, 0)
		s.EnabledUsers[r.Name] = make([]int, 0)
	}

	// Compute users of resources.
	idx := 0
	for sig_idx, sig := range signatures {
		for i, r := range sig.Inputs {
			// output should be the same logical resource
			for _, j := range sig.ForwardMap[i] {
				if r.Name == sig.Outputs[j].Name {
					s.Users[r.Name] = append(s.Users[r.Name], &ResourceUser{
						true, sig_idx, sig.SyscallID, r.Path, sig.Outputs[j].Path, i, j,
					})
					s.EnabledUsers[r.Name] = append(s.EnabledUsers[r.Name], idx)
					idx += 1
				}
			}
		}
	}

	return &s
}

func (t *Target) BuildResourceNode(schema *TargetSchema, min_res string, depth int) *ResourceNode {
	ref := ResourceNodeRef{depth, min_res}
	if node, ok := schema.ResourceNodes[ref]; ok {
		return node
	}

	node := t.buildResourceNodeInner(schema, min_res, depth)
	if node != nil {
		schema.ResourceNodes[ref] = node
	}
	return node
}

func (t *Target) buildResourceNodeInner(schema *TargetSchema, min_res string, depth int) *ResourceNode {
	if depth < 0 {
		return nil
	}

	node := ResourceNode{
		Enabled:         false,
		SpecialValue:    false,
		MinRes:          min_res,
		Children:        make([]SigNode, 0),
		EnabledChildren: make([]int, 0),
	}

	// Find all signatures that can produce/consume this resource.
	//
	// There are several different situations for resource matching:
	//
	// 1. The signature uses a more general resource than the one we are looking for, e.g. we need to construct
	//    "custom_fd" but the sig is defined on "fd". In this case, we can use the signature but we need to
	//    constrain the matching input to be at least "custom_fd". If there is no matching input, we cannot use
	//    the signature.
	//
	// 2. The signature uses a more specific (or equal) resource than the one we are looking for, e.g. we need
	//    to construct "fd" but the sig is defined on "custom_fd". Here, we can use the signature and the constraint
	//    on the matching input is already satisfied (matching input must be at least "custom_fd").
	//
	// 3. The signature uses an incompatible resource, e.g. we need to construct "custom_fd" but the sig is defined on
	//    "custom_fd2". In this case, we cannot use the signature.
	for sig_idx, sig := range schema.Signatures {
		// If we are already at max depth (0) skip signatures that take other inputs.
		// Only allowed signatures are pure constructors.
		if depth == 0 && len(sig.Inputs) > 0 {
			continue
		}

		for out_idx, out := range sig.Outputs {
			var matching_res string
			var matching_in_idx int

			if schema.isMoreGeneral(out.Name, min_res) {

				// We can only use this signature if it is not the constructor for this resource.
				if len(sig.ReverseMap[out_idx]) == 0 {
					continue
				}

				// Valid but extend constraint on matching input.
				matching_res = min_res
			} else if schema.isMoreSpecificOrEq(out.Name, min_res) {
				// Valid
				matching_res = out.Name
			} else {
				// Invalid
				continue
			}

			if len(sig.ReverseMap[out_idx]) > 1 {
				panic("Multiple inputs to a single output not supported")
			} else if len(sig.ReverseMap[out_idx]) == 0 {
				matching_in_idx = -1
			} else {
				matching_in_idx = sig.ReverseMap[out_idx][0]
			}

			sig_node := SigNode{
				Enabled:        true,
				OutResourceIdx: out_idx,
				SigIdx:         sig_idx,
				SyscallID:      sig.SyscallID,
				Inputs:         make([]ResourceNodeRef, len(sig.Inputs)),
			}

			// Iterate other inputs to this signature.
			for in_idx, in := range sig.Inputs {
				var in_min_res string
				if in_idx == matching_in_idx {
					in_min_res = matching_res
				} else {
					in_min_res = in.Name
				}

				inner_node := t.BuildResourceNode(schema, in_min_res, depth-1)
				sig_node.Inputs[in_idx] = ResourceNodeRef{
					MaxDepth: depth - 1,
					MinRes:   in_min_res,
				}

				if inner_node != nil {
					sig_node.Enabled = (sig_node.Enabled && inner_node.Enabled)
				} else {
					sig_node.Enabled = false
				}
			}

			if sig_node.Enabled {
				node.Children = append(node.Children, sig_node)
				node.Enabled = true
				node.EnabledChildren = append(node.EnabledChildren, len(node.Children)-1)
			}
		}
	}

	return &node
}

func (g *GraphProg) Complete(ctx *GraphMutationContext) {
	if ctx.Verbose {
		fmt.Println("[Graph: pre-complete]")
		g.DebugPrint()
	}

	missing_inputs := EdgeList{Edges: make([]EdgeRef, 0)}
	free_outputs := EdgeList{Edges: make([]EdgeRef, 0)}

	for conn_node, node := range g.Nodes {
		for conn_idx, conn := range node.Inputs {
			if conn.NodeIdx == -1 || conn.NodeIdx == -2 {
				res := conn.Resource.Type().Name()
				if g.Target.isAnyRes(res) {
					continue
				}

				// Attempt to find the minimum input res that will satisfy all downstream nodes.
				// If there is a conflict, we default to the exact specified resource by this syscall.
				min_res := g.MinimumInputRes(conn_node, conn_idx)
				if min_res == "" {
					min_res = node.Inputs[conn_idx].Resource.Type().Name()
				}

				missing_inputs.push(EdgeRef{
					Resource: min_res,
					NodeIdx:  conn_node,
					ConnIdx:  conn_idx,
					Input:    true,
					Level:    node.Level,
					MaxDepth: ctx.TargetSchema.MaxDepth,
				})
			}
		}

		for conn_idx, conn := range node.Outputs {
			if conn.NodeIdx == -1 || conn.NodeIdx == -2 {
				res := g.MaximumOutputRes(conn_node, conn_idx)
				if res == "" {
					continue
				}

				free_outputs.push(EdgeRef{
					Resource: res,
					NodeIdx:  conn_node,
					ConnIdx:  conn_idx,
					Input:    true,
					Level:    node.Level,
					MaxDepth: 0, // unused
				})
			}
		}
	}

	for missing_inputs.size() > 0 {
		inp := missing_inputs.pop()
		ctx.Logf("- Completing %v (%v remaining inputs) (%v free outputs)\n", inp, missing_inputs.size(), free_outputs.size())
		g.completeOne(ctx, inp, &missing_inputs, &free_outputs)
	}
}

func (g *GraphProg) completeOne(ctx *GraphMutationContext, inp EdgeRef, missing_inputs *EdgeList, free_outputs *EdgeList) {
	res_node := ctx.TargetSchema.GetMinConstructor(inp.Resource)

	var missing_res bool = false

	if res_node == nil {
		log.Errorf("Missing resource constructor: %s\n", inp.Resource)
		missing_res = true
	} else if len(res_node.Children) == 0 {
		log.Errorf("Resource has no children: %s\n", inp.Resource)
		missing_res = true
	} else if !res_node.Enabled {
		log.Errorf("Resource is disabled: %s\n", inp.Resource)
		missing_res = true
	}

	if missing_res {
		// panic("Missing resource constructor")

		r := ctx.TargetSchema.target.GetResourceDesc(inp.Resource)
		if len(r.Values) > 0 {
			v := r.Values[ctx.Rand.Intn(len(r.Values))]

			r := g.Nodes[inp.NodeIdx].Inputs[inp.ConnIdx].Resource
			r.Res = nil
			r.Val = v
			r.uses = nil

			g.Nodes[inp.NodeIdx].Inputs[inp.ConnIdx].NodeIdx = -3
			g.Nodes[inp.NodeIdx].Inputs[inp.ConnIdx].ConnIdx = -3
		}

	} else {
		g.appendTree(ctx, inp, res_node, missing_inputs, free_outputs)
	}
}

func (g *GraphProg) appendTree(ctx *GraphMutationContext, inp EdgeRef, res_node *ResourceNode, missing_inputs *EdgeList, free_outputs *EdgeList) {
	ctx.Logf(" - AppendTree(%+v)\n", inp)

	// Check if we can reuse a free resource instead of adding new syscalls.
	if ctx.Rand.Float32() < ctx.FreqReuse {
		ctx.Logf(" -- Trying to reuse resource\n")

		avail_outputs := make([]struct {
			Edge EdgeRef
			Idx  int
		}, 0)

		for out_idx, out := range free_outputs.Edges {
			// We can use a free input if it is the same or more specific than the input we need.
			if out.Level < inp.Level && ctx.TargetSchema.isMoreSpecificOrEq(out.Resource, inp.Resource) {
				avail_outputs = append(avail_outputs, struct {
					Edge EdgeRef
					Idx  int
				}{
					out,
					out_idx,
				})
			}
		}

		if len(avail_outputs) > 0 {
			out_idx := ctx.Rand.Intn(len(avail_outputs))
			out := avail_outputs[out_idx]

			ctx.Logf(" -- Linking existing resource (%v:%v)[level=%v] --> (%v:%v)[level=%v]\n", out.Edge.NodeIdx, out.Edge.ConnIdx, out.Edge.Level, inp.NodeIdx, inp.ConnIdx, inp.Level)

			// Link the output.
			g.Link(out.Edge.NodeIdx, out.Edge.ConnIdx, inp.NodeIdx, inp.ConnIdx)

			// Remove the free output.
			free_outputs.remove(out.Idx)
			return
		} else {
			ctx.Logf(" -- No suitable existing resources\n")
		}
	}

	var sig_node *SigNode

	// Use GCT 95% of the time.
	if ctx.GCT != nil && ctx.Rand.Float32() < 0.95 {
		// Try to find a suitable signature using the graph choice table.

		syscallID := g.Nodes[inp.NodeIdx].Meta.ID
		inputPath := g.Nodes[inp.NodeIdx].Inputs[inp.ConnIdx].Path

		// fmt.Printf("-- try GCT: %v %v\n", syscallID, inputPath)
		// fmt.Printf("syscall name: %v\n", ctx.TargetSchema.target.Syscalls[syscallID].Name)

		entry := ctx.GCT.ChoosePred(ctx.Rand, syscallID, inputPath)
		if entry != nil {
			// fmt.Printf(" -- Found GCT entry: %v\n", entry)
			// fmt.Printf(" -- syscall name: %v\n", ctx.TargetSchema.target.Syscalls[entry.SigIdx].Name)

			// Find a template for this syscall/resource pair.
			run_key := RunKey{entry.SigIdx, entry.Path}
			if sigs, ok := ctx.TargetSchema.SignatureProducers[run_key]; ok {
				if len(sigs) > 0 {
					sig_idx := sigs[ctx.Rand.Intn(len(sigs))]

					for _, idx := range res_node.EnabledChildren {
						if res_node.Children[idx].SigIdx == sig_idx {
							sig_node = &res_node.Children[idx]
							// fmt.Printf(" -- Found GCT template: %v\n", sig_node)
							break
						}
					}
				}
			} else {
				// if !ctx.TargetSchema.InvalidSyscalls[entry.SigIdx] {
				// 	poss := ctx.TargetSchema.SignaturesBySyscall[entry.SigIdx]
				// 	for _, p := range poss {
				// 		s := ctx.TargetSchema.Signatures[p]
				// 		s.DebugPrint()
				// 	}
				// 	fmt.Printf(" -- No signature found for GCT entry: %v\n", run_key)
				// 	panic("No signature found")
				// }
			}
		}
	}

	if sig_node == nil {
		// If GCT is not enabled, or failed to find a syscall, pick a random compatible one

		if len(res_node.EnabledChildren) == 0 {
			// Bail out, no enabled children.
			return
		}

		// Pick a random enabled signature for this resource tree.
		c_idx := ctx.Rand.Intn(len(res_node.EnabledChildren))
		sig_node = &res_node.Children[res_node.EnabledChildren[c_idx]]
	}

	sig := ctx.TargetSchema.Signatures[sig_node.SigIdx]

	new_level := inp.Level - 1

	state := analyzeGraph(ctx.CT, ctx.Corpus, g, len(g.Nodes)-1)
	node := CreateFromTemplate(&sig, new_level, ctx.TargetSchema.target, ctx.Rand, state, ctx.Verbose)
	new_idx := g.AddCallNode(node)

	g.Link(new_idx, sig_node.OutResourceIdx, inp.NodeIdx, inp.ConnIdx)

	ctx.Logf(" -- adding signature: (%v)\n", ctx.TargetSchema.target.Syscalls[sig.SyscallID].Name)
	if ctx.Verbose {
		sig.DebugPrint()
	}
	ctx.Logf("    Link(%v:%v)[level=%v] --> (%v:%v)[level=%v]\n", new_idx, sig_node.OutResourceIdx, new_level, inp.NodeIdx, inp.ConnIdx, inp.Level)

	if inp.MaxDepth == 0 {
		if len(sig_node.Inputs) > 0 {
			panic("Expected no inputs")
		}
	}

	// Recursively add inputs to this new syscall
	for i, child := range sig_node.Inputs {
		ctx.Logf("    Input %v: %+v\n", i, child)
		g.appendTree(ctx, EdgeRef{
			Resource: child.MinRes,
			NodeIdx:  new_idx,
			ConnIdx:  i,
			Input:    true,
			Level:    new_level,
			MaxDepth: inp.MaxDepth - 1,
		}, ctx.TargetSchema.ResourceNodes[child], missing_inputs, free_outputs)
	}

	// TODO: maybe update free outputs after appending tree. It is a bit tricky because we can only determine the
	// base type for a free output after there exists a constructor for it in the graph. E.g. a free output that is linked
	// upstream to a missing input has no well-defined base type.
}

func (g *GraphProg) MarkAll() {
	for _, node := range g.Nodes {
		node.Marked = true
	}
}

func (g *GraphProg) UnmarkAll() {
	for _, node := range g.Nodes {
		node.Marked = false
	}
}

func (g *GraphProg) MarkConnected(node_idx int) {
	visited := make(map[int]bool)
	g.visit(node_idx, true, &visited)
}

func (g *GraphProg) UnmarkConnected(node_idx int) {
	visited := make(map[int]bool)
	g.visit(node_idx, false, &visited)
}

func (g *GraphProg) visit(node_idx int, mark bool, visited *map[int]bool) {
	node := g.Nodes[node_idx]
	node.Marked = mark
	(*visited)[node_idx] = true
	for _, conn := range node.Inputs {
		if conn.NodeIdx >= 0 {
			if !(*visited)[conn.NodeIdx] {
				g.visit(conn.NodeIdx, mark, visited)
			}
		}
	}
	for _, conn := range node.Outputs {
		if conn.NodeIdx >= 0 {
			if !(*visited)[conn.NodeIdx] {
				g.visit(conn.NodeIdx, mark, visited)
			}
		}
	}
}

// Simplify the graph to retain only the nodes in the given set.
func (g *GraphProg) KeepMarked() {
	write_idx := 0
	for read_idx, node := range g.Nodes {
		if node.Marked {
			if read_idx != write_idx {
				g.ReindexNode(node, write_idx)
				g.Nodes[write_idx] = node
			}
			write_idx++
		}
	}
	g.Nodes = g.Nodes[:write_idx]
}

// Updates the neighboring connections to this node with a new index.
func (g *GraphProg) ReindexNode(node *CallNode, new_idx int) {
	old_idx := node.Index
	node.Index = new_idx

	// fmt.Printf("ReindexNode(%v, %v) :: %+v\n", old_idx, new_idx, node)

	for in_idx, conn := range node.Inputs {
		if conn.NodeIdx >= 0 {
			if conn.NodeIdx == old_idx {
				// Self loop
				node.Inputs[in_idx].NodeIdx = new_idx
			} else {
				// Update the neighbor's connection to this node.
				other := g.Nodes[conn.NodeIdx]
				other.Outputs[conn.ConnIdx].NodeIdx = new_idx
			}
		}
	}
	for out_idx, conn := range node.Outputs {
		if conn.NodeIdx >= 0 {
			if conn.NodeIdx == old_idx {
				// Self loop
				node.Outputs[out_idx].NodeIdx = new_idx
			} else {
				// Update the neighbor's connection to this node.
				other := g.Nodes[conn.NodeIdx]
				other.Inputs[conn.ConnIdx].NodeIdx = new_idx
			}
		}
	}
}

func (g *GraphProg) ShiftIndex(offset int) {
	for idx := range g.Nodes {
		node := g.Nodes[idx]
		node.Index += offset
		for i := range node.Inputs {
			if node.Inputs[i].NodeIdx >= 0 {
				node.Inputs[i].NodeIdx += offset
			}
		}
		for i := range node.Outputs {
			if node.Outputs[i].NodeIdx >= 0 {
				node.Outputs[i].NodeIdx += offset
			}
		}
	}
}

func (g *GraphProg) ShiftLevel(offset int) {
	for idx := range g.Nodes {
		node := g.Nodes[idx]
		node.Level += offset
	}
}

func (g *GraphProg) MaxLevel() int {
	max := 0
	for _, node := range g.Nodes {
		if node.Level > max {
			max = node.Level
		}
	}
	return max
}

func (g *GraphProg) MinLevel() int {
	min := 0
	for _, node := range g.Nodes {
		if node.Level < min {
			min = node.Level
		}
	}
	return min
}

// Set the level of a given node and recursively propagate this change.
// Useful if we need to insert a node between two others.
//
// Allows graphs to have self loops (as generated by builtin syzkaller stuff).
func (g *GraphProg) UpdateLevels(idx int, level int, ctx *GraphMutationContext, count int) {
	ctx.Logf("UpdateLevels(%v, %v)\n", idx, level)

	if count > 200 {
		ctx.Logf("bailing!")
		panic("loop in update levels")
	}

	node := g.Nodes[idx]
	node.Level = level
	for _, conn := range node.Inputs {
		if conn.NodeIdx >= 0 && conn.NodeIdx != node.Index && g.Nodes[conn.NodeIdx].Level >= level {
			g.UpdateLevels(conn.NodeIdx, level-1, ctx, count+1)
		}
	}
	for _, conn := range node.Outputs {
		if conn.NodeIdx >= 0 && conn.NodeIdx != node.Index && g.Nodes[conn.NodeIdx].Level <= level {
			g.UpdateLevels(conn.NodeIdx, level+1, ctx, count+1)
		}
	}
}

func (g *GraphProg) MutateSpliceIn(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateSpliceIn]\n")

	edges := make([]struct {
		ResourceRange []string
		NodeIdx       int
		ConnIdx       int
	}, 0)

	for node_idx, node := range g.Nodes {
		for conn_idx, conn := range node.Outputs {
			// Avoid unconnected nodes and self-loops.
			if conn.NodeIdx < 0 || conn.NodeIdx == node_idx {
				continue
			}

			// Compute the resource bounds for an intermediate node.
			max_res := g.MaximumOutputRes(node_idx, conn_idx)
			min_res := g.MinimumInputRes(conn.NodeIdx, conn.ConnIdx)

			if max_res == "" {
				return false
				// panic("No constructor found for resource while determining splice-in bounds")
			}

			if min_res == "" {
				// If there is a downstream conflict, default to using the previously connected resource.
				// TODO: should we default to the constructor type instead?
				max_res = conn.Resource.Type().Name()
				min_res = conn.Resource.Type().Name()
			}

			res_range := resourceRange(ctx.TargetSchema.target, min_res, max_res)
			edges = append(edges, struct {
				ResourceRange []string
				NodeIdx       int
				ConnIdx       int
			}{res_range, node_idx, conn_idx})
		}
	}

	if len(edges) == 0 {
		ctx.Logf("- No edges found\n")
		return false
	}

	edge := edges[ctx.Rand.Intn(len(edges))]

	syscallA := g.Nodes[edge.NodeIdx].Meta.ID
	outA := g.Nodes[edge.NodeIdx].Outputs[edge.ConnIdx].Path
	nodeB := g.Nodes[edge.NodeIdx].Outputs[edge.ConnIdx].NodeIdx
	syscallB := g.Nodes[nodeB].Meta.ID
	inB := g.Nodes[nodeB].Inputs[g.Nodes[edge.NodeIdx].Outputs[edge.ConnIdx].ConnIdx].Path

	users_nodep := make([]*ResourceUser, 0)

	users_dep := make([]struct {
		CumProb int
		User    *ResourceUser
	}, 0)

	cumprob := 0
	for _, res := range edge.ResourceRange {
		for _, idx := range ctx.TargetSchema.EnabledUsers[res] {
			user := ctx.TargetSchema.Users[res][idx]
			users_nodep = append(users_nodep, user)

			// Check if this user would satisfy a dependency.
			if ctx.GCT != nil {
				// Weight between A-U
				w1 := ctx.GCT.GetScore(syscallA, user.SigIdx, outA, user.InputPath)

				// Weight between U-B
				w2 := ctx.GCT.GetScore(user.SigIdx, syscallB, user.OutputPath, inB)

				w := w1 + w2
				if w > 0 {
					users_dep = append(users_dep, struct {
						CumProb int
						User    *ResourceUser
					}{cumprob + w, user})
					cumprob += w
				}
			}
		}
	}

	if len(users_nodep) == 0 {
		ctx.Logf("- No users found\n")
		return false
	}

	var user *ResourceUser
	using_dep := false
	if len(users_dep) > 0 {
		using_dep = true
		prob := ctx.Rand.Intn(cumprob)
		ind := sort.Search(len(users_dep), func(i int) bool {
			return users_dep[i].CumProb > prob
		})
		user = users_dep[ind].User
	} else {
		user = users_nodep[ctx.Rand.Intn(len(users_nodep))]
	}

	ctx.Logf("- Selected user: %v :: (%d)-(%s)-(%d) -- with dep: %v\n", edge.ResourceRange, user.InputPath, ctx.TargetSchema.target.Syscalls[ctx.TargetSchema.Signatures[user.SigIdx].SyscallID].Name, user.OutputPath, using_dep)

	// Unlink old connection.
	b_node := g.Nodes[edge.NodeIdx].Outputs[edge.ConnIdx].NodeIdx
	b_conn := g.Nodes[edge.NodeIdx].Outputs[edge.ConnIdx].ConnIdx
	g.Unlink(edge.NodeIdx, edge.ConnIdx)

	ctx.Logf("- Splicing in %v between (%d:%d) and (%d:%d)\n", edge.ResourceRange, edge.NodeIdx, edge.ConnIdx, b_node, b_conn)

	// Create new node.
	sig := ctx.TargetSchema.Signatures[user.SigIdx]
	state := analyzeGraph(ctx.CT, ctx.Corpus, g, len(g.Nodes)-1)
	new_node := CreateFromTemplate(&sig, g.Nodes[edge.NodeIdx].Level+1, ctx.TargetSchema.target, ctx.Rand, state, ctx.Verbose)
	new_idx := g.AddCallNode(new_node)

	// Link new node.
	g.Link(edge.NodeIdx, edge.ConnIdx, new_idx, user.InputIdx)
	g.Link(new_idx, user.OutputIdx, b_node, b_conn)

	// Update levels.
	g.UpdateLevels(new_idx, g.Nodes[edge.NodeIdx].Level+1, ctx, 0)

	g.Complete(ctx)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepSpliceIn{
			NodeA:     edge.NodeIdx,
			ConnA:     edge.ConnIdx,
			NodeB:     b_node,
			ConnB:     b_conn,
			SigIdx:    user.SigIdx,
			SyscallID: ctx.TargetSchema.Signatures[user.SigIdx].SyscallID,
			UsedGCT:   using_dep,
		})
	}

	return true
}

func (g *GraphProg) MutateSpliceOut(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateSpliceOut]\n")

	// A node is removable if there is at least one resource that "passes through" this syscall, e.g. a pair
	// of edges one input, one output, that are linked via the inner map.
	//
	// Additionally, all of the other outbound edges that are in use (and don't have an associated input edge) must be constructable.
	removable := make([]int, 0)

outer:
	for node_idx, node := range g.Nodes {

		has_passthrough := false

		for in_idx, conn := range node.Inputs {
			// Avoid unconnected nodes and self-loops.
			if conn.NodeIdx < 0 || conn.NodeIdx == node_idx {
				continue
			}

			for out_map_idx, out_idx := range node.ForwardMap[in_idx] {
				conn2 := node.Outputs[out_idx]
				if conn2.NodeIdx >= 0 {
					// Note: only the first mapped output will be spliced, the second one will need to be constructed.
					if out_map_idx == 0 {
						has_passthrough = true
					} else {
						res := conn2.Resource.Type().Name()
						if !ctx.TargetSchema.IsConstructable(res) {
							continue outer
						}
					}
				}
			}
		}

		// Iterate the resources that need to be constructed by this node and abort if any of them are not constructable.
		for _, out_idx := range node.ForwardMap[-1] {
			conn2 := node.Outputs[out_idx]
			if conn2.NodeIdx >= 0 {
				res := conn2.Resource.Type().Name()
				if !ctx.TargetSchema.IsConstructable(res) {
					continue outer
				}
			}
		}

		if has_passthrough {
			removable = append(removable, node_idx)
		}
	}

	if len(removable) == 0 {
		ctx.Logf("- No removable nodes found\n")
		return false
	}

	node := removable[ctx.Rand.Intn(len(removable))]
	ctx.Logf("- Splicing out node %d\n", node)

	g.MarkAll()
	g.UnmarkConnected(node)

	linked := make([]int, 0)

	for in_idx := range g.Nodes[node].Inputs {
		for out_map_idx, out_idx := range g.Nodes[node].ForwardMap[in_idx] {
			conn := g.Nodes[node].Inputs[in_idx]
			conn2 := g.Nodes[node].Outputs[out_idx]
			if conn2.NodeIdx >= 0 {
				if conn.NodeIdx >= 0 {
					// In + Out
					ctx.Logf("    UnlinkBackward(%d, %d)\n", node, in_idx)
					g.UnlinkBackward(node, in_idx)
					ctx.Logf("    Unlink(%d, %d)\n", node, out_idx)
					g.Unlink(node, out_idx)

					if out_map_idx == 0 {
						// Link the two nodes together (only first outbound edge)
						ctx.Logf("- Linking (%d:%d) to (%d:%d)\n", conn.NodeIdx, conn.ConnIdx, conn2.NodeIdx, conn2.ConnIdx)
						g.Link(conn.NodeIdx, conn.ConnIdx, conn2.NodeIdx, conn2.ConnIdx)
						linked = append(linked, conn.NodeIdx)
					}
				} else {
					// Out only
					ctx.Logf("    Unlink(%d, %d)\n", node, out_idx)
					g.Unlink(node, out_idx)
				}
			} else {
				if conn.NodeIdx >= 0 {
					// In only
					ctx.Logf("    UnlinkBackward(%d, %d)\n", node, in_idx)
					g.UnlinkBackward(node, in_idx)
				}
			}
		}
	}

	for _, out_idx := range g.Nodes[node].ForwardMap[-1] {
		conn2 := g.Nodes[node].Outputs[out_idx]
		if conn2.NodeIdx >= 0 {
			// Out only
			ctx.Logf("    Unlink(%d, %d)\n", node, out_idx)
			g.Unlink(node, out_idx)
		}
	}

	for _, node_idx := range linked {
		g.MarkConnected(node_idx)
	}

	// Update here before we lose information.
	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepSpliceOut{
			RemovedNode: node,
			SyscallID:   g.Nodes[node].Meta.ID,
		})
	}

	g.KeepMarked()
	g.UnmarkAll()

	g.Complete(ctx)

	return true
}

func (g *GraphProg) MutateCrosslink(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateCrosslink]\n")
	return g.crosslinkInner(ctx, len(g.Nodes), 0)
}

func (g *GraphProg) MutateCrossover(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateCrossover]\n")

	if len(ctx.Corpus) == 0 {
		ctx.Logf("- No corpus\n")
		return false
	}

	orig_size := len(g.Nodes)

	prog_b := ctx.Corpus[ctx.Rand.Intn(len(ctx.Corpus))].Clone()
	g2 := ProgToGraph(prog_b)
	g2.ShiftIndex(len(g.Nodes))
	g2.ShiftLevel(g.MaxLevel() - g2.MinLevel() + 1)

	g.Nodes = append(g.Nodes, g2.Nodes...)
	g.Comments = append(g.Comments, g2.Comments...)

	if ctx.Verbose {
		fmt.Println("[Graph: pre-crosslink inner]")
		g.DebugPrint()
	}

	return g.crosslinkInner(ctx, orig_size, orig_size)
}

// Given a node at level L with output of type Z and a node at level L2 > L with input of type Z,
// link the two nodes together and discard the previous connected components.
func (g *GraphProg) crosslinkInner(ctx *GraphMutationContext, producerMax int, consumerMin int) bool {
	if len(g.Nodes) < 2 {
		ctx.Logf("- Not enough nodes\n")
		return false
	}

	// Keep a list of all possible output edges to choose from.
	producers := make([]struct {
		// The most specific resource type that can be used by this edge.
		MaxResource string
		NodeIdx     int
		ConnIdx     int
		ConnPath    ResourcePath
	}, 0)

	for node_idx, node := range g.Nodes[:producerMax] {
		if node_idx >= producerMax {
			break
		}
		for conn_idx, conn := range node.Outputs {
			// Avoid unconnected nodes and self-loops.
			if conn.NodeIdx < 0 || conn.NodeIdx == node_idx {
				continue
			}
			res_out := conn.Resource.Type().Name()
			res_in := g.Nodes[conn.NodeIdx].Inputs[conn.ConnIdx].Resource.Type().Name()

			if ctx.TargetSchema.target.isAnyRes(res_in) || ctx.TargetSchema.target.isAnyRes(res_out) {
				continue
			}

			// res_out/res_in may be different; ensure we can construct the input resource.
			if ctx.TargetSchema.IsConstructable(res_in) {

				// Determine the most specific resource type that can be used by this edge.
				max_res := g.MaximumOutputRes(node_idx, conn_idx)
				if max_res == "" {
					max_res = res_out
				}

				producers = append(producers, struct {
					MaxResource string
					NodeIdx     int
					ConnIdx     int
					ConnPath    ResourcePath
				}{max_res, node_idx, conn_idx, conn.Path})
			}
		}
	}

	if len(producers) == 0 {
		ctx.Logf("- No producers found\n")
		return false
	}

	// Pick a random producer
	producer := producers[ctx.Rand.Intn(len(producers))]
	avoid_idx := g.Nodes[producer.NodeIdx].Outputs[producer.ConnIdx].NodeIdx
	start_level := g.Nodes[producer.NodeIdx].Level

	// Find consumers for the same resource type after the start level
	consumers_nodep := make([]struct {
		NodeIdx int
		ConnIdx int
	}, 0)

	consumers_dep := make([]struct {
		CumProb int
		NodeIdx int
		ConnIdx int
	}, 0)

	cumprob := 0

	for node_idx, node := range g.Nodes {
		if node_idx < consumerMin {
			continue
		}
		if node.Level <= start_level || node_idx == avoid_idx || node_idx == producer.NodeIdx {
			continue
		}
		for conn_idx, conn := range node.Inputs {
			if conn.NodeIdx < 0 {
				continue
			}

			min_res := g.MinimumInputRes(node_idx, conn_idx)
			if min_res == "" {
				min_res = conn.Resource.Type().Name()
			}

			if ctx.TargetSchema.isMoreSpecificOrEq(producer.MaxResource, min_res) {
				consumers_nodep = append(consumers_nodep, struct {
					NodeIdx int
					ConnIdx int
				}{node_idx, conn_idx})

				if ctx.GCT != nil {
					// Check if there is a dependency between the producer and consumer.

					w := ctx.GCT.GetScore(
						g.Nodes[producer.NodeIdx].Meta.ID,
						g.Nodes[node_idx].Meta.ID,
						producer.ConnPath,
						conn.Path,
					)
					if w > 0 {
						consumers_dep = append(consumers_dep, struct {
							CumProb int
							NodeIdx int
							ConnIdx int
						}{cumprob + w, node_idx, conn_idx})
						cumprob += w
					}
				}
			}
		}
	}

	if len(consumers_nodep) == 0 {
		ctx.Logf("- No consumers found\n")
		return false
	}

	// Pick a random consumer
	var consumer struct {
		NodeIdx int
		ConnIdx int
	}

	using_dep := false

	// Prefer consumers with dependencies
	if len(consumers_dep) > 0 {
		using_dep = true
		prob := ctx.Rand.Intn(cumprob)
		ind := sort.Search(len(consumers_dep), func(i int) bool {
			return consumers_dep[i].CumProb > prob
		})
		consumer = struct {
			NodeIdx int
			ConnIdx int
		}{consumers_dep[ind].NodeIdx, consumers_dep[ind].ConnIdx}
	} else {
		consumer = consumers_nodep[ctx.Rand.Intn(len(consumers_nodep))]
	}

	ctx.Logf("- Crosslink between (%d:%d) and (%d:%d) -- from dep: %v\n", producer.NodeIdx, producer.ConnIdx, consumer.NodeIdx, consumer.ConnIdx, using_dep)

	g.MarkAll()
	g.UnmarkConnected(g.Nodes[producer.NodeIdx].Outputs[producer.ConnIdx].NodeIdx)
	g.UnmarkConnected(g.Nodes[consumer.NodeIdx].Inputs[consumer.ConnIdx].NodeIdx)

	g.Unlink(producer.NodeIdx, producer.ConnIdx)
	g.UnlinkBackward(consumer.NodeIdx, consumer.ConnIdx)
	g.Link(producer.NodeIdx, producer.ConnIdx, consumer.NodeIdx, consumer.ConnIdx)

	g.MarkConnected(producer.NodeIdx)

	g.KeepMarked()
	g.UnmarkAll()

	// Completion may be necessary if the subgraphs previously connected to producer and consumer are still connected to the rest of the graph.
	g.Complete(ctx)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepCrosslink{
			NodeA:   producer.NodeIdx,
			ConnA:   producer.ConnIdx,
			NodeB:   consumer.NodeIdx,
			ConnB:   consumer.ConnIdx,
			UsedGCT: using_dep,
		})
	}

	return true
}

// Swap the index of two nodes at the same level.
// (implicitly swaps their order in the graph)
func (g *GraphProg) MutatePriority(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutatePriority]\n")

	a := ctx.Rand.Intn(len(g.Nodes))

	other := make([]int, 0)
	for i, node := range g.Nodes {
		if node.Level == g.Nodes[a].Level && i != a {
			other = append(other, i)
		}
	}

	if len(other) == 0 {
		return false
	}

	b := other[ctx.Rand.Intn(len(other))]

	g.ReindexNode(g.Nodes[a], b)
	g.ReindexNode(g.Nodes[b], a)

	g.Nodes[a], g.Nodes[b] = g.Nodes[b], g.Nodes[a]

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepPriority{
			NodeA: a,
			NodeB: b,
		})
	}

	return true
}

func (g *GraphProg) MutateReplaceConstructor(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateReplaceConstructor]\n")

	consumers := make([]struct {
		NodeIdx  int
		ConnIdx  int
		Resource string
	}, 0)

	for node_idx, node := range g.Nodes {
		for conn_idx, conn := range node.Inputs {
			// Avoid unconnected nodes and self-loops.
			if conn.NodeIdx < 0 || conn.NodeIdx == node_idx {
				continue
			}

			min_res_in := g.MinimumInputRes(node_idx, conn_idx)
			if min_res_in == "" {
				continue
			}

			if ctx.TargetSchema.IsConstructable(min_res_in) {
				consumers = append(consumers, struct {
					NodeIdx  int
					ConnIdx  int
					Resource string
				}{node_idx, conn_idx, min_res_in})
			}
		}
	}

	if len(consumers) == 0 {
		ctx.Logf("- No consumers found\n")
		return false
	}

	consumer := consumers[ctx.Rand.Intn(len(consumers))]

	ctx.Logf("- Replacing constructor for %s at (%d:%d)\n", consumer.Resource, consumer.NodeIdx, consumer.ConnIdx)

	g.MarkAll()
	g.UnmarkConnected(consumer.NodeIdx)

	g.UnlinkBackward(consumer.NodeIdx, consumer.ConnIdx)
	g.MarkConnected(consumer.NodeIdx)

	g.KeepMarked()
	g.UnmarkAll()

	g.Complete(ctx)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepReplaceConstructor{
			Node: consumer.NodeIdx,
			Conn: consumer.ConnIdx,
		})
	}

	return true
}

// Pick a random node and keep only the subgraph containing that node.
func (g *GraphProg) MutateIsolateGraph(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateIsolateGraph]\n")

	before := len(g.Nodes)
	g.MarkConnected(ctx.Rand.Intn(len(g.Nodes)))
	g.KeepMarked()
	g.UnmarkAll()
	after := len(g.Nodes)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepIsolateGraph{
			Before: before,
			After:  after,
		})
	}

	return true
}

// Invokes the syzkaller mutateArg mutator
func (g *GraphProg) MutateWrappedMutateArg(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateWrappedMutateArg]\n")

	prog := GraphToProg(g)
	before := string(prog.SerializeVerbose())
	ctx.Logf("Before: %s\n", before)

	prog.WrappedMutateArg(rand.NewSource(ctx.Rand.Int63()), ctx.MaxNodes, ctx.CT, ctx.NoMutate, ctx.Corpus)

	after := string(prog.SerializeVerbose())
	ctx.Logf("After: %s\n", after)

	g2 := ProgToGraph(prog)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepWrappedMutateArg{})
	}

	// Overwrite g with g2
	g.Nodes = g2.Nodes
	g.Comments = g2.Comments

	return true
}

func (g *GraphProg) MutateInsertNode(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateInsertNode]\n")

	// Pick a random enabled syscall
	if len(ctx.TargetSchema.enabledSignatures) == 0 {
		ctx.Logf("- No enabled syscalls\n")
		return false
	}

	sig_idx := pickSeedTemplate(ctx, 40)

	// enabled_idx := ctx.Rand.Intn(len(ctx.TargetSchema.enabledSignatures))
	// sig_idx := ctx.TargetSchema.enabledSignatures[enabled_idx]
	sig := ctx.TargetSchema.Signatures[sig_idx]

	// Pick a random level near other syscalls
	min_level := 0
	max_level := 0
	for _, node := range g.Nodes {
		if node.Level < min_level {
			min_level = node.Level
		}
		if node.Level > max_level {
			max_level = node.Level
		}
	}
	min_level -= 2
	max_level += 2
	level := ctx.Rand.Intn(max_level-min_level) + min_level

	if ctx.Verbose {
		fmt.Printf("Inserting syscall %v at level %v\n", ctx.TargetSchema.target.Syscalls[sig.SyscallID].Name, level)
		sig.DebugPrint()
	}
	state := analyzeGraph(ctx.CT, ctx.Corpus, g, len(g.Nodes)-1)
	node := CreateFromTemplate(&sig, level, ctx.TargetSchema.target, ctx.Rand, state, ctx.Verbose)
	g.AddCallNode(node)

	g.Complete(ctx)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepInsertNode{
			SigIdx: sig_idx,
			Level:  level,
		})
	}

	return true
}

func (g *GraphProg) MutateInPlace(ctx *GraphMutationContext) bool {
	ctx.Logf("[MutateInPlace]\n")

	// Pick a random node weighted by complexity
	prios := make([]float64, len(g.Nodes))
	var prio_sum float64 = 0

	for i, node := range g.Nodes {
		c := 0
		if !node.Meta.Attrs.NoGenerate {
			for _, ctx := range node.Context {
				c += argComplexity(ctx)
			}
		}
		prios[i] = float64(c) + prio_sum
		prio_sum += float64(c)
	}

	if prio_sum == 0 {
		ctx.Logf("- No complexity\n")
		return false
	}

	node_idx := sort.SearchFloat64s(prios, ctx.Rand.Float64()*prio_sum)

	r := newRandExisting(ctx.TargetSchema.target, ctx.Rand)
	state := analyzeGraph(ctx.CT, ctx.Corpus, g, len(g.Nodes)-1)

	node := g.Nodes[node_idx]
	for i := range node.Context {
		mutateArgInPlace(node.Context[i], ctx, state, r)
	}

	ctx.TargetSchema.target.assignSizesArray(node.Context, node.Meta.Args, nil)

	if ctx.History != nil {
		ctx.History.Steps = append(ctx.History.Steps, GraphMutationStepWrappedMutateArg{})
	}

	return true
}

func argComplexity(arg Arg) int {
	if arg == nil {
		return 0
	}

	switch a := arg.(type) {
	case *ResultArg:
		return 0
	case *GroupArg:
		complexity := 0
		for _, inner := range a.Inner {
			complexity += argComplexity(inner)
		}
		return complexity
	case *PointerArg:
		return argComplexity(a.Res)
	case *UnionArg:
		return argComplexity(a.Option)
	default:
		return 1
	}
}

func mutateArgInPlace(arg Arg, ctx *GraphMutationContext, s *state, r *randGen) {
	if arg == nil {
		return
	}

	switch a := arg.(type) {
	case *ResultArg:
		break
	case *GroupArg:
		for idx := range a.Inner {
			mutateArgInPlace(a.Inner[idx], ctx, s, r)
		}
	case *PointerArg:
		mutateArgInPlace(a.Res, ctx, s, r)
	case *UnionArg:
		mutateArgInPlace(a.Option, ctx, s, r)
	default:
		newArg, calls := r.generateArg(s, arg.Type(), arg.GetDir())
		if len(calls) > 0 {
			panic("unexpected calls")
		}
		replaceArg(arg, newArg)
	}
}

func (g *GraphProg) MarkCallForRemoval(idx int) {
	node := g.Nodes[idx]
	for _, conn := range node.Inputs {
		if conn.NodeIdx >= 0 {
			other := g.Nodes[conn.NodeIdx]
			other.Outputs[conn.ConnIdx].NodeIdx = -1
		}
	}
	for _, conn := range node.Outputs {
		if conn.NodeIdx >= 0 {
			other := g.Nodes[conn.NodeIdx]

			if other.Comment == "syzgrapher pseudo endpoint" {
				other.Marked = false
			} else {
				other.Inputs[conn.ConnIdx].NodeIdx = -1
			}
		}
	}
	node.Marked = false
}

func (g *GraphProg) TrimToMax(ctx *GraphMutationContext) {
	if g.NumRealNodes() <= ctx.MaxNodes {
		return
	} else {
		ctx.Logf("Trimming graph, original size: %v\n", g.NumRealNodes())
	}

	g.MarkAll()

	byLayer := make([]*CallNode, 0)
	byLayer = append(byLayer, g.Nodes...)

	// Sort by layer (primary) and index (secondary).
	sort.Slice(byLayer, func(i, j int) bool {
		if byLayer[i].Level == byLayer[j].Level {
			return byLayer[i].Index < byLayer[j].Index
		}
		return byLayer[i].Level < byLayer[j].Level
	})

	count := 0
	for _, node := range byLayer {
		if node.Comment == "syzgrapher pseudo endpoint" {
			continue
		} else {
			if count < ctx.MaxNodes {
				count++
			} else {
				// Remove this node.
				g.MarkCallForRemoval(node.Index)
			}
		}
	}

	g.KeepMarked()
}

func Generate(ctx *GraphMutationContext) *GraphProg {
	idx := pickSeedTemplate(ctx, 10)

	// Create a new graph with the seed syscall.
	graph := &GraphProg{
		Target:   ctx.TargetSchema.target,
		Nodes:    make([]*CallNode, 0),
		Comments: make([]string, 0),
	}

	state := analyzeGraph(ctx.CT, ctx.Corpus, graph, 0)
	node := CreateFromTemplate(&ctx.TargetSchema.Signatures[idx], 0, ctx.TargetSchema.target, ctx.Rand, state, ctx.Verbose)
	graph.AddCallNode(node)

	graph.Complete(ctx)

	// Occasional mutation to increase diversity.
	if ctx.Rand.Intn(100) < 10 {
		graph.Mutate(ctx)
	}

	return graph
}

func pickSeedTemplate(ctx *GraphMutationContext, full_ratio int) int {
	seen := make(map[int]bool)
	for _, p := range ctx.Corpus {
		for _, c := range p.Calls {
			seen[c.Meta.ID] = true
		}
	}

	valid_sys := make([]int, 0)
	for i := range ctx.TargetSchema.target.Syscalls {
		if !seen[i] && ctx.TargetSchema.enabledCalls[i] && len(ctx.TargetSchema.SignaturesBySyscall[i]) > 0 {
			valid_sys = append(valid_sys, i)
		}
	}

	if len(valid_sys) == 0 || ctx.Rand.Intn(100) < full_ratio {
		// Random enabled signature
		eidx := ctx.Rand.Intn(len(ctx.TargetSchema.enabledSignatures))
		return ctx.TargetSchema.enabledSignatures[eidx]
	} else {
		sys_idx := valid_sys[ctx.Rand.Intn(len(valid_sys))]
		return ctx.TargetSchema.SignaturesBySyscall[sys_idx][ctx.Rand.Intn(len(ctx.TargetSchema.SignaturesBySyscall[sys_idx]))]
	}
}

// Performs a random graph mutation.
func (g *GraphProg) Mutate(ctx *GraphMutationContext) {
	// Set and log a new seed so mutations are more easily reproducible.
	// seed := ctx.Rand.Int63()
	// ctx.Logf("Mutate (seed=%v)\n", seed)
	// ctx.Rand.Seed(seed)

	g.MutateSeeded(ctx)
}

func (g *GraphProg) MutateSeeded(ctx *GraphMutationContext) {
	if ctx.Verbose {
		fmt.Println("Graph: pre-mutate")
		g.DebugPrint()
	}

	weight := make([]int, MutationCount)

	mutations := 0
	stop := false

	for {
		if mutations >= MaxMutationSteps {
			stop = true
		}

		if mutations >= 1 && ctx.Rand.Intn(100) < 10 {
			stop = true
		}

		if stop {
			break
		}

		// Reset mutation weights for this mutation step
		weight[MutationCrosslink] = 10
		weight[MutationCrossover] = 10
		weight[MutationPriority] = 5
		weight[MutationReplaceConstructor] = 5
		weight[MutationSpliceIn] = 20
		weight[MutationInsertNode] = 20
		weight[MutationInPlace] = 20

		// Loop until we successfully run a mutator.
		for {
			max_weight := 0
			for i := 0; i < MutationCount; i++ {
				max_weight += weight[i]
			}

			if max_weight == 0 {
				fmt.Printf("all failed\n")
				stop = true
				break
			}

			mut := ctx.Rand.Intn(max_weight)
			idx := 0
			for ; idx < MutationCount; idx++ {
				if mut < weight[idx] {
					break
				}
				mut -= weight[idx]
			}

			// Now do the mutation
			ok := false
			switch idx {
			case MutationCrosslink:
				ok = g.MutateCrosslink(ctx)
			case MutationCrossover:
				ok = g.MutateCrossover(ctx)
			case MutationPriority:
				ok = g.MutatePriority(ctx)
			case MutationReplaceConstructor:
				ok = g.MutateReplaceConstructor(ctx)
			case MutationSpliceIn:
				ok = g.MutateSpliceIn(ctx)
			case MutationInsertNode:
				ok = g.MutateInsertNode(ctx)
			case MutationInPlace:
				ok = g.MutateInPlace(ctx)
			default:
				panic("unknown mutation")
			}

			if ok {
				// Trim after each successful mutation.
				g.TrimToMax(ctx)
				mutations++
				break
			} else {
				// We failed to run a particular mutator, so disable it.
				weight[idx] = 0
			}
		}
	}

	if ctx.Verbose {
		fmt.Println("Graph: post-mutate")
		g.DebugPrint()
	}

	if ctx.Verbose {
		// If running in verbose mode, do a quick check to make sure we didn't introduce a disabled syscall.
		// This helps trace down bugs in mutators.
		g.PostValidate(ctx.TargetSchema)
	}
}

func (g *GraphProg) HasSelfReference() bool {
	for _, node := range g.Nodes {
		for _, conn := range node.Outputs {
			if conn.NodeIdx == node.Index {
				return true
			}
		}
	}
	return false
}

func (g *GraphProg) PostValidate(s *TargetSchema) {
	for _, node := range g.Nodes {
		if !s.enabledCalls[node.Meta.ID] {
			fmt.Printf("Bad syscall: %v (%v)\n", node.Meta, node.Meta.Name)
			panic("Disabled syscall after mutation")
		}
	}
}

func (g *GraphProg) DebugPrint() {
	for i, node := range g.Nodes {
		syscall := "(pseudo destructor)"
		if node.Comment != "syzgrapher pseudo endpoint" {
			syscall = node.Meta.Name
		}
		fmt.Printf("Node %d: index=%d, level=%d, syscall=%s\n", i, node.Index, node.Level, syscall)
		for j, conn := range node.Inputs {
			fmt.Printf("  Input %d: %d:%d res=%s path=%v\n", j, conn.NodeIdx, conn.ConnIdx, conn.Resource.Type().Name(), SliceResourcePath(conn.Path))
		}
		for j, conn := range node.Outputs {
			fmt.Printf("  Output %d: %d:%d res=%s path=%v\n", j, conn.NodeIdx, conn.ConnIdx, conn.Resource.Type().Name(), SliceResourcePath(conn.Path))
		}
		ForeachArgGraph(node, func(arg Arg, isRet bool, path ResourcePath) {
			fmt.Printf("  > %v", SliceResourcePath(path))
			if isRet {
				fmt.Printf(" (ret)\n")
				return
			}
			fmt.Printf(" %v\n", arg.Type())
		})
	}
}

// Compares two resources and returns the more specific one.
// If they are incompatible, returns the empty string.
func mostSpecificResource(t *Target, res1, res2 string) string {
	if res1 == "" || res2 == "" {
		return ""
	}

	if t.isAnyRes(res1) {
		return res2
	}
	if t.isAnyRes(res2) {
		return res1
	}

	k1 := t.resourceMap[res1].Kind
	k2 := t.resourceMap[res2].Kind

	if len(k1) > len(k2) {
		for i := 0; i < len(k2); i++ {
			if k1[i] != k2[i] {
				return ""
			}
		}
		return res1
	} else {
		for i := 0; i < len(k1); i++ {
			if k1[i] != k2[i] {
				return ""
			}
		}
		return res2
	}
}

// Given two resources min_res and max_res representing the most general and most specific resources,
// compute a list of all resources between (and including) them.
//
// Returns an empty list if the resources are incompatible.
func resourceRange(t *Target, min_res, max_res string) []string {
	if min_res == "" || max_res == "" {
		return []string{}
	}

	k1 := t.resourceMap[min_res].Kind
	k2 := t.resourceMap[max_res].Kind

	if t.isAnyRes(min_res) {
		return k2
	}

	if len(k1) < 1 || len(k2) < 1 {
		return []string{}
	}

	// k1: [a, b, c]
	// k2: [a, b, c, d, e, f]
	// res: [c, d, e, f]

	if len(k2) > len(k1) {
		for i := 0; i < len(k1); i++ {
			if k1[i] != k2[i] {
				// incompatible
				return []string{}
			}
		}
		return k2[len(k1)-1:]
	} else {
		return []string{}
	}
}

// Returns the minimally specific resource as bounded by downstream nodes.
// i.e. inputs here must be at least as specific as this resource
//
// Returns the empty string if downstream resources force a conflict.
func (g *GraphProg) MinimumInputRes(node, idx int) string {
	res := g.Nodes[node].Inputs[idx].Resource.Type().Name()
	for _, idx := range g.Nodes[node].ForwardMap[idx] {
		out := g.Nodes[node].Outputs[idx]

		if out.NodeIdx < 0 {
			// Ignore disconnected outputs.
			continue
		}

		res = mostSpecificResource(g.Target, res, g.MinimumInputRes(out.NodeIdx, out.ConnIdx))

		if res == "" {
			return ""
		}
	}
	return res
}

// Returns the maximally specific resource as bounded by the constructor node.
// i.e. outputs here can be at most as specific as this resource
// If there is no constructor node, returns the empty string.
func (g *GraphProg) MaximumOutputRes(node, idx int) string {
	// We find the constructor by tracing backwards until either finding the constructor or a disconnected input.
	currNode := node
	currOutIdx := idx

	for {
		inputs := g.Nodes[currNode].ReverseMap[currOutIdx]

		if len(inputs) == 0 {
			// This is the constructor.
			return g.Nodes[currNode].Outputs[currOutIdx].Resource.Type().Name()
		} else if len(inputs) > 1 {
			panic("Multiple inputs to a node while searching for constructor")
		} else {
			// Follow the input.
			inputIdx := inputs[0]
			input := g.Nodes[currNode].Inputs[inputIdx]

			if input.NodeIdx < 0 {
				if input.NodeIdx == -3 {
					// Special value.
					return g.Nodes[currNode].Outputs[currOutIdx].Resource.Type().Name()
				} else {
					// Disconnected input.
					return ""
				}
			}

			currNode = input.NodeIdx
			currOutIdx = input.ConnIdx
		}
	}
}

// Returns true if any of the nodes have a type input with no valid constructions.
// I.e. there are two downstream nodes that require incompatible resources.
func (g *GraphProg) HasInconsistency() bool {
	for node := range g.Nodes {
		for conn := range g.Nodes[node].Inputs {
			res := g.MinimumInputRes(node, conn)
			if res == "" {
				return true
			}
		}
	}
	return false
}

func (g *GraphProg) GetInputSpecificity(node, idx int) (upcast bool, downcast bool, anycast bool, invalid bool) {
	inp := g.Nodes[node].Inputs[idx]
	res := inp.Resource.Type().Name()

	if inp.NodeIdx < 0 {
		// Disconnected input.
		if inp.NodeIdx == -3 {
			// Special value.
			return false, false, false, false
		} else {
			return false, false, false, true
		}
	}

	max_res := g.MaximumOutputRes(inp.NodeIdx, inp.ConnIdx)

	if max_res == "" {
		// No constructor found.
		return false, false, false, true
	}

	if res == max_res {
		// exact match
		return false, false, false, false
	}

	k1 := g.Target.resourceMap[res].Kind
	k2 := g.Target.resourceMap[max_res].Kind

	if g.Target.isAnyRes(res) {
		// anycast
		return false, false, true, false
	}

	if len(k1) > len(k2) {
		for i := 0; i < len(k2); i++ {
			if k1[i] != k2[i] {
				// incompatible
				return false, false, false, true
			}
		}
		// downcast, target resource is more specific that constructed one
		return false, true, false, false
	} else {
		for i := 0; i < len(k1); i++ {
			if k1[i] != k2[i] {
				// incompatible
				return false, false, false, true
			}
		}
		// upcast, target resource is less specific than constructed one
		return true, false, false, false
	}
}
