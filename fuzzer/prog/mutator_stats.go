package prog

import (
	"fmt"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Represents all mutations:
	InfoGlobal = iota

	// Built-in mutators:
	InfoMutate
	InfoMutateSquashAny
	InfoMutateSplice
	InfoMutateInsertCall
	InfoMutateMutateArg
	InfoMutateRemoveCall

	// Graph-based mutators:
	InfoGraph
	InfoGraphSpliceIn
	InfoGraphSpliceOut
	InfoGraphCrosslink
	InfoGraphPriority
	InfoGraphIsolateGraph
	InfoGraphReplaceConstructor
	InfoGraphWrappedMutateArg
	InfoGraphInsertNode

	InfoCount
)

// Number of different program sizes to track.
const InfoSizes = 40

var MutatorInfoNames = [InfoCount]string{
	InfoGlobal: "global",

	InfoMutate:           "mutate",
	InfoMutateSquashAny:  "mutate_squash_any",
	InfoMutateSplice:     "mutate_splice",
	InfoMutateInsertCall: "mutate_insert_call",
	InfoMutateMutateArg:  "mutate_mutate_arg",
	InfoMutateRemoveCall: "mutate_remove_call",

	InfoGraph:                   "graph",
	InfoGraphSpliceIn:           "graph_splice_in",
	InfoGraphSpliceOut:          "graph_splice_out",
	InfoGraphCrosslink:          "graph_crosslink",
	InfoGraphPriority:           "graph_priority",
	InfoGraphIsolateGraph:       "graph_isolate_graph",
	InfoGraphReplaceConstructor: "graph_replace_constructor",
	InfoGraphWrappedMutateArg:   "graph_wrapped_mutate_arg",
	InfoGraphInsertNode:         "graph_insert_node",
}

type MutatorStats struct {
	Buckets [InfoCount][InfoSizes]BucketInfo
}

// Stats for a single mutator/size bucket.
//
// Most of these statistics are collected per test-case. If a mutator was used multiple times
// in a single test-case, it will count as just one attempt.
type BucketInfo struct {
	// How many times was this mutator attempted (including multiple per test-case)
	TotalAttempts uint64

	// In how many test-cases was this mutator attempted
	Attempts uint64

	// How many times was this mutator used in a test-case that resulted in a duplicate.
	Collisions uint64

	// How many times was this mutator used in a test-case that resulted in a new signal (added to corpus).
	NewSignal uint64

	// How many times was this mutator used in a test-case that resulted in an invalid program structure (type mismatch):

	// Program was invalid before.
	PreInvalid uint64

	// Program was invalid after.
	PostInvalid uint64

	// Mutation steps were empty (only for InfoMutate and InfoGraph).
	NoSteps uint64
}

type MutatorInfoProm struct {
	// Labels: mutator, size
	TotalAttempts *prometheus.GaugeVec
	Attempts      *prometheus.GaugeVec
	Collisions    *prometheus.GaugeVec
	NewSignal     *prometheus.GaugeVec
	PreInvalid    *prometheus.GaugeVec
	PostInvalid   *prometheus.GaugeVec
	NoSteps       *prometheus.GaugeVec
}

func NewMutatorInfoProm() *MutatorInfoProm {
	return &MutatorInfoProm{
		TotalAttempts: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_total_attempts",
			Help: "Total attempts for mutator",
		}, []string{"mutator", "size"}),
		Attempts: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_attempts",
			Help: "Attempts for mutator",
		}, []string{"mutator", "size"}),
		Collisions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_collisions",
			Help: "Collisions for mutator",
		}, []string{"mutator", "size"}),
		NewSignal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_new_signal",
			Help: "New signal for mutator",
		}, []string{"mutator", "size"}),
		PreInvalid: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_pre_invalid",
			Help: "Pre invalid for mutator",
		}, []string{"mutator", "size"}),
		PostInvalid: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_post_invalid",
			Help: "Post invalid for mutator",
		}, []string{"mutator", "size"}),
		NoSteps: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mutatorinfo_no_steps",
			Help: "No steps for mutator",
		}, []string{"mutator", "size"}),
	}
}

func (p *MutatorInfoProm) Register() {
	prometheus.MustRegister(p.TotalAttempts)
	prometheus.MustRegister(p.Attempts)
	prometheus.MustRegister(p.Collisions)
	prometheus.MustRegister(p.NewSignal)
	prometheus.MustRegister(p.PreInvalid)
	prometheus.MustRegister(p.PostInvalid)
	prometheus.MustRegister(p.NoSteps)
}

func (p *MutatorInfoProm) Reset() {
	for i := range MutatorInfoNames {
		name := MutatorInfoNames[i]
		for j := 0; j < InfoSizes; j++ {
			size := fmt.Sprintf("%02d", j+1)
			p.TotalAttempts.WithLabelValues(name, size).Set(0)
			p.Attempts.WithLabelValues(name, size).Set(0)
			p.Collisions.WithLabelValues(name, size).Set(0)
			p.NewSignal.WithLabelValues(name, size).Set(0)
			p.PreInvalid.WithLabelValues(name, size).Set(0)
			p.PostInvalid.WithLabelValues(name, size).Set(0)
			p.NoSteps.WithLabelValues(name, size).Set(0)
		}
	}
}

func NewMutatorStats() *MutatorStats {
	return &MutatorStats{
		Buckets: [InfoCount][InfoSizes]BucketInfo{},
	}
}

func (i *BucketInfo) CloneReset() BucketInfo {
	return BucketInfo{
		Attempts:    atomic.SwapUint64(&i.Attempts, 0),
		Collisions:  atomic.SwapUint64(&i.Collisions, 0),
		NewSignal:   atomic.SwapUint64(&i.NewSignal, 0),
		PreInvalid:  atomic.SwapUint64(&i.PreInvalid, 0),
		PostInvalid: atomic.SwapUint64(&i.PostInvalid, 0),
		NoSteps:     atomic.SwapUint64(&i.NoSteps, 0),
	}
}

func (s *MutatorStats) CloneReset() MutatorStats {
	st := MutatorStats{
		Buckets: [InfoCount][InfoSizes]BucketInfo{},
	}

	for i := range s.Buckets {
		for j := range s.Buckets[i] {
			st.Buckets[i][j] = s.Buckets[i][j].CloneReset()
		}
	}

	return st
}

func (s *MutatorInfoProm) Observe(other *MutatorStats) {
	for i := range other.Buckets {
		name := MutatorInfoNames[i]
		for j := range other.Buckets[i] {
			size := fmt.Sprintf("%02d", j+1)
			bucket := other.Buckets[i][j]
			s.TotalAttempts.WithLabelValues(name, size).Add(float64(bucket.TotalAttempts))
			s.Attempts.WithLabelValues(name, size).Add(float64(bucket.Attempts))
			s.Collisions.WithLabelValues(name, size).Add(float64(bucket.Collisions))
			s.NewSignal.WithLabelValues(name, size).Add(float64(bucket.NewSignal))
			s.PreInvalid.WithLabelValues(name, size).Add(float64(bucket.PreInvalid))
			s.PostInvalid.WithLabelValues(name, size).Add(float64(bucket.PostInvalid))
			s.NoSteps.WithLabelValues(name, size).Add(float64(bucket.NoSteps))
		}
	}
}

func (i *BucketInfo) Update(total uint64, new_signal bool, collision bool, pre_invalid bool, post_invalid bool, no_steps bool) {
	atomic.AddUint64(&i.TotalAttempts, total)
	atomic.AddUint64(&i.Attempts, 1)
	if new_signal {
		atomic.AddUint64(&i.NewSignal, 1)
	}
	if collision {
		atomic.AddUint64(&i.Collisions, 1)
	}
	if pre_invalid {
		atomic.AddUint64(&i.PreInvalid, 1)
	}
	if post_invalid {
		atomic.AddUint64(&i.PostInvalid, 1)
	}
	if no_steps {
		atomic.AddUint64(&i.NoSteps, 1)
	}
}

func (s *MutatorStats) PostExecute(prog *Prog, new_signal bool, collision bool) {
	if prog.Origin == nil {
		// Not called directly after mutation stage.
		return
	}

	graph := ProgToGraph(prog.Clone())

	pre_invalid := false // TODO
	post_invalid := graph.HasInconsistency()
	size := uint64(len(graph.Nodes))

	if size > InfoSizes {
		panic("Program size too large")
	}
	if size == 0 {
		panic("Program size zero")
	}

	s.Buckets[InfoGlobal][size-1].Update(1, new_signal, collision, pre_invalid, post_invalid, false)

	// Individual mutator counts
	counts := make(map[int]int)

	switch origin := (*prog.Origin).(type) {
	case OriginMutated:
		no_steps := len(origin.Steps) == 0
		s.Buckets[InfoMutate][size-1].Update(1, new_signal, collision, pre_invalid, post_invalid, no_steps)

		for _, step := range origin.Steps {
			switch step.(type) {
			case MutationStepSplice:
				counts[InfoMutateSplice]++
			case MutationStepSquashAny:
				counts[InfoMutateSquashAny]++
			case MutationStepInsertCall:
				counts[InfoMutateInsertCall]++
			case MutationStepMutateArg:
				counts[InfoMutateMutateArg]++
			case MutationStepRemoveCall:
				counts[InfoMutateRemoveCall]++
			default:
				panic("Unknown mutation step: " + fmt.Sprintf("%T", step))
			}
		}
	case OriginMutatedGraph:
		no_steps := len(origin.Steps) == 0
		s.Buckets[InfoGraph][size-1].Update(1, new_signal, collision, pre_invalid, post_invalid, no_steps)

		for _, step := range origin.Steps {
			switch step.(type) {
			case GraphMutationStepSpliceIn:
				counts[InfoGraphSpliceIn]++
			case GraphMutationStepSpliceOut:
				counts[InfoGraphSpliceOut]++
			case GraphMutationStepCrosslink:
				counts[InfoGraphCrosslink]++
			case GraphMutationStepPriority:
				counts[InfoGraphPriority]++
			case GraphMutationStepIsolateGraph:
				counts[InfoGraphIsolateGraph]++
			case GraphMutationStepReplaceConstructor:
				counts[InfoGraphReplaceConstructor]++
			case GraphMutationStepWrappedMutateArg:
				counts[InfoGraphWrappedMutateArg]++
			case GraphMutationStepInsertNode:
				counts[InfoGraphInsertNode]++
			default:
				panic("Unknown graph mutation step: " + fmt.Sprintf("%T", step))
			}
		}
	default:
		fmt.Printf("Unexpected origin type: %v\n", origin)
		panic("Unexpected origin type")
	}

	for k, v := range counts {
		if v > 0 {
			s.Buckets[k][size-1].Update(uint64(v), new_signal, collision, pre_invalid, post_invalid, false)
		}
	}
}
