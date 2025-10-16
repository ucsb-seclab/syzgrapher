package prog

import (
	"encoding/gob"
	"encoding/json"

	"github.com/google/uuid"
)

type ProgOrigin interface {
	isProgOrigin()
}

type OriginSeedCorpus struct {
}

type OriginGenerated struct {
}

type OriginMutated struct {
	Parent uuid.UUID
	Steps  []MutationStep
}

type OriginMutatedWithHints struct {
	Parent uuid.UUID
}

type OriginMutatedCollide struct {
	Parent uuid.UUID
}

type OriginMinimized struct {
	Parent uuid.UUID
}

type OriginMutatedGraph struct {
	Parent uuid.UUID
	Steps  []GraphMutationStep
}

func (OriginSeedCorpus) isProgOrigin()       {}
func (OriginGenerated) isProgOrigin()        {}
func (OriginMutated) isProgOrigin()          {}
func (OriginMutatedWithHints) isProgOrigin() {}
func (OriginMutatedCollide) isProgOrigin()   {}
func (OriginMinimized) isProgOrigin()        {}
func (OriginMutatedGraph) isProgOrigin()     {}

func (o OriginSeedCorpus) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": "seed",
	})
}

func (o OriginGenerated) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": "generated",
	})
}

func (o OriginMutated) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "mutated",
		"parent": o.Parent,
		"steps":  o.Steps,
	})
}

func (o OriginMutatedWithHints) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "mutated_with_hints",
		"parent": o.Parent,
	})
}

func (o OriginMutatedCollide) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "mutated_collide",
		"parent": o.Parent,
	})
}

func (o OriginMinimized) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "minimized",
		"parent": o.Parent,
	})
}

func (o OriginMutatedGraph) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "mutated_graph",
		"parent": o.Parent,
		"steps":  o.Steps,
	})
}

type MutationStep interface {
	isMutationStep()
}

type MutationStepSquashAny struct {
}

type MutationStepSplice struct {
	Other     uuid.UUID
	OtherSize int
	Index     int
	Truncated int // How many calls were truncated (if above limit)
}

type MutationStepInsertCall struct {
	CallIndex       int
	SyscallID       int
	ConstructorSize int
	Truncated       int
}

type MutationStepMutateArg struct {
	CallIndex int
}

type MutationStepRemoveCall struct {
	CallIndex int
}

func (MutationStepSquashAny) isMutationStep()  {}
func (MutationStepSplice) isMutationStep()     {}
func (MutationStepInsertCall) isMutationStep() {}
func (MutationStepMutateArg) isMutationStep()  {}
func (MutationStepRemoveCall) isMutationStep() {}

func (m MutationStepSquashAny) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": "squash_any",
	})
}

func (m MutationStepSplice) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":       "splice",
		"other":      m.Other,
		"other_size": m.OtherSize,
		"index":      m.Index,
		"truncated":  m.Truncated,
	})
}

func (m MutationStepInsertCall) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":             "insert_call",
		"call_index":       m.CallIndex,
		"syscall_id":       m.SyscallID,
		"constructor_size": m.ConstructorSize,
		"truncated":        m.Truncated,
	})
}

func (m MutationStepMutateArg) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":       "mutate_arg",
		"call_index": m.CallIndex,
	})
}

func (m MutationStepRemoveCall) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":       "remove_call",
		"call_index": m.CallIndex,
	})
}

type GraphMutationStep interface {
	isGraphMutationStep()
}

type GraphMutationStepSpliceIn struct {
	NodeA     int
	ConnA     int
	NodeB     int
	ConnB     int
	SigIdx    int
	SyscallID int
	UsedGCT   bool
}

type GraphMutationStepSpliceOut struct {
	RemovedNode int
	SyscallID   int
}

type GraphMutationStepCrosslink struct {
	NodeA   int
	ConnA   int
	NodeB   int
	ConnB   int
	UsedGCT bool
}

type GraphMutationStepInterleave struct {
	ProgB uuid.UUID
}

type GraphMutationStepPriority struct {
	NodeA int
	NodeB int
}

type GraphMutationStepIsolateGraph struct {
	Before int
	After  int
}

type GraphMutationStepReplaceConstructor struct {
	Node int
	Conn int
}

type GraphMutationStepWrappedMutateArg struct{}

type GraphMutationStepInsertNode struct {
	SigIdx int
	Level  int
}

func (GraphMutationStepSpliceIn) isGraphMutationStep()           {}
func (GraphMutationStepSpliceOut) isGraphMutationStep()          {}
func (GraphMutationStepCrosslink) isGraphMutationStep()          {}
func (GraphMutationStepPriority) isGraphMutationStep()           {}
func (GraphMutationStepIsolateGraph) isGraphMutationStep()       {}
func (GraphMutationStepReplaceConstructor) isGraphMutationStep() {}
func (GraphMutationStepWrappedMutateArg) isGraphMutationStep()   {}
func (GraphMutationStepInsertNode) isGraphMutationStep()         {}

func (m GraphMutationStepSpliceIn) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":       "splice_in",
		"node_a":     m.NodeA,
		"conn_a":     m.ConnA,
		"node_b":     m.NodeB,
		"conn_b":     m.ConnB,
		"sig_idx":    m.SigIdx,
		"syscall_id": m.SyscallID,
		"used_gct":   m.UsedGCT,
	})
}

func (m GraphMutationStepSpliceOut) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":         "splice_out",
		"removed_node": m.RemovedNode,
		"syscall_id":   m.SyscallID,
	})
}

func (m GraphMutationStepCrosslink) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":     "crosslink",
		"node_a":   m.NodeA,
		"conn_a":   m.ConnA,
		"node_b":   m.NodeB,
		"conn_b":   m.ConnB,
		"used_gct": m.UsedGCT,
	})
}

func (m GraphMutationStepPriority) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "priority",
		"node_a": m.NodeA,
		"node_b": m.NodeB,
	})
}

func (m GraphMutationStepIsolateGraph) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":   "isolate_graph",
		"before": m.Before,
		"after":  m.After,
	})
}

func (m GraphMutationStepReplaceConstructor) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": "replace_constructor",
		"node": m.Node,
		"conn": m.Conn,
	})
}

func (m GraphMutationStepWrappedMutateArg) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": "wrapped_mutate_arg",
	})
}

func (m GraphMutationStepInsertNode) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type":    "insert_node",
		"sig_idx": m.SigIdx,
		"level":   m.Level,
	})
}

func RegisterAllOrigin() {
	gob.Register(OriginSeedCorpus{})
	gob.Register(OriginGenerated{})
	gob.Register(OriginMutated{})
	gob.Register(OriginMutatedWithHints{})
	gob.Register(OriginMutatedCollide{})
	gob.Register(OriginMinimized{})
	gob.Register(OriginMutatedGraph{})

	gob.Register(MutationStepSquashAny{})
	gob.Register(MutationStepSplice{})
	gob.Register(MutationStepInsertCall{})
	gob.Register(MutationStepMutateArg{})
	gob.Register(MutationStepRemoveCall{})

	gob.Register(GraphMutationStepSpliceIn{})
	gob.Register(GraphMutationStepSpliceOut{})
	gob.Register(GraphMutationStepCrosslink{})
	gob.Register(GraphMutationStepPriority{})
	gob.Register(GraphMutationStepIsolateGraph{})
	gob.Register(GraphMutationStepReplaceConstructor{})
	gob.Register(GraphMutationStepWrappedMutateArg{})
	gob.Register(GraphMutationStepInsertNode{})

	gob.Register(&SampleGuideArray{})
	gob.Register(&SampleGuideFree{})
	gob.Register(&SampleGuideFreeReset{})
	gob.Register(&SampleGuideResource{})
	gob.Register(&SampleGuideOptional{})
	gob.Register(&SampleGuideUnion{})
	gob.Register(&SampleGuidePtr{})
	gob.Register(&SampleGuideStruct{})
}
