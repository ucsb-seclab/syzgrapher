package syzgrapher

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	//"strings"

	"github.com/google/syzkaller/prog"
)

// define struct to match JSON file
/*
type DepInfo struct {
	Syscall_Level  map[string]map[string]float64
	Resource_Level map[string]map[string]map[string]float64
}
*/

type ResultDep struct {
	Key  string
	Prob float64
}

type ArgDepInfo = map[string]map[string]map[string]map[string]float64

func loadGraphChoiceTableForward(path string, target *prog.Target) *prog.StaticGraphChoiceTable {
	g := prog.StaticGraphChoiceTable{
		//SyscallRuns:  make([][]prog.StaticEntry, len(target.Syscalls)),
		//ResourceRuns: make([]map[string][]prog.StaticEntry, len(target.Syscalls)),
		ArgRuns: make([]map[int][]prog.StaticEntry, len(target.Syscalls)),
	}

	// read JSON file
	/*
		content, err := ioutil.ReadFile(path)
		if err != nil {
			// TODO change to just print error but continue fuzzing
			panic(fmt.Sprintf("failed to read depinfo.json: %v", err))
		}

		var depinfo DepInfo
		err = json.Unmarshal(content, &depinfo)
		if err != nil {
			panic(fmt.Sprintf("failed to unmarshal depinfo.json: %v", err))
		}

		// fill in gct
		for s_ch := range depinfo.Syscall_Level {
			syscall_ch := target.SyscallMap[s_ch]
			cumpr := 0
			for s_set, prob := range depinfo.Syscall_Level[s_ch] {
				// fill in g.SyscallRuns
				cumpr += int(prob * 1000000)
				ent := prog.StaticEntry{
					CumProb:     cumpr,
					CheckerName: s_ch,
					SetName:     s_set,
				}
				if len(g.SyscallRuns[syscall_ch.ID]) == 0 {
					g.SyscallRuns[syscall_ch.ID] = []prog.StaticEntry{ent}
				} else {
					g.SyscallRuns[syscall_ch.ID] = append(g.SyscallRuns[syscall_ch.ID], ent)
				}
			}
		}

		for s_ch := range depinfo.Resource_Level {
			syscall_ch := target.SyscallMap[s_ch]
			g.ResourceRuns[syscall_ch.ID] = make(map[string][]prog.StaticEntry)
			for s_set, r_map := range depinfo.Resource_Level[s_ch] {
				syscall_set := target.SyscallMap[s_set]
				cum_prob := 0
				g.ResourceRuns[syscall_ch.ID][syscall_set.Name] = make([]prog.StaticEntry, 0)
				res_deps := []ResultDep{}
				for key, prob := range r_map {
					// fill in g.ResourceRuns
					sp := strings.Split(key, "-")
					r_id1 := len(syscall_ch.Args)
					if sp[0] == "r" {
						res_deps = append(res_deps, ResultDep{Key: key, Prob: prob})
						continue
					} else if sp[0] != "x" && sp[0] != "r" {
						r_id1, _ = strconv.Atoi(sp[0])
					} else if sp[0] == "x" {
						r_id1 = find_res(syscall_ch)
					}
					r_id2 := len(syscall_set.Args)
					if sp[1] != "x" && sp[1] != "r" {
						r_id2, _ = strconv.Atoi(sp[1])
					} else if sp[1] == "x" {
						r_id2 = find_res(syscall_set)
					}
					ent := prog.StaticEntry{
						CumProb:       int(prob*1000000) + cum_prob,
						CheckerName:   s_ch,
						SetName:       s_set,
						ArgCheckIndex: r_id1,
						ArgSetIndex:   r_id2,
					}
					cum_prob += int(prob * 1000000)
					tmp := g.ResourceRuns[syscall_ch.ID][syscall_set.Name]
					tmp = append(tmp, ent)
					g.ResourceRuns[syscall_ch.ID][syscall_set.Name] = tmp
				}
				// add return value dependency to all arguments
				resource_args := get_res(syscall_ch)
				for _, res_dep := range res_deps {
					s_arg := len(syscall_set.Args)
					sp := strings.Split(res_dep.Key, "-")
					if sp[1] != "x" && sp[1] != "r" {
						s_arg, _ = strconv.Atoi(sp[1])
					} else if sp[1] == "x" {
						s_arg = find_res(syscall_set)
					}

					for _, c_arg := range resource_args {
						found := false
						cumprob := 0
						for _, ent := range g.ResourceRuns[syscall_ch.ID][syscall_set.Name] {
							if ent.CheckerName == s_ch && ent.SetName == s_set &&
								ent.ArgCheckIndex == c_arg &&
								ent.ArgSetIndex == s_arg {
								ent.CumProb += int(res_dep.Prob*1000000) / len(resource_args)
								found = true
							} else if found {
								ent.CumProb += int(res_dep.Prob*1000000) / len(resource_args)
							}
							cumprob = ent.CumProb
						}
						if !found {
							ent := prog.StaticEntry{
								CumProb:       int(res_dep.Prob*1000000)/len(resource_args) + cumprob,
								CheckerName:   s_ch,
								SetName:       s_set,
								ArgCheckIndex: c_arg,
								ArgSetIndex:   s_arg,
							}
							g.ResourceRuns[syscall_ch.ID][syscall_set.Name] = append(g.ResourceRuns[syscall_ch.ID][syscall_set.Name], ent)
						}
					}
				}
			}
		}
	*/

	return &g
}

func loadGraphChoiceTableBackward(path string, target *prog.Target) *prog.StaticGraphChoiceTable {
	g := prog.StaticGraphChoiceTable{
		//SyscallRuns:  make([][]prog.StaticEntry, len(target.Syscalls)),
		//ResourceRuns: make([]map[string][]prog.StaticEntry, len(target.Syscalls)),
		ArgRuns: make([]map[int][]prog.StaticEntry, len(target.Syscalls)),
	}

	// read JSON file
	/*
		content, err := ioutil.ReadFile(path)
		if err != nil {
			// TODO change to just print error but continue fuzzing
			panic(fmt.Sprintf("failed to read depinfo.json: %v", err))
		}

		var depinfo DepInfo
		err = json.Unmarshal(content, &depinfo)
		if err != nil {
			panic(fmt.Sprintf("failed to unmarshal depinfo.json: %v", err))
		}

		// fill in gct
		for s_set := range depinfo.Syscall_Level {
			syscall_set := target.SyscallMap[s_set]
			cumpr := 0
			for s_ch, prob := range depinfo.Syscall_Level[s_set] {
				// fill in g.SyscallRuns
				cumpr += int(prob * 1000000)
				ent := prog.StaticEntry{
					CumProb:     cumpr,
					CheckerName: s_ch,
					SetName:     s_set,
				}
				if len(g.SyscallRuns[syscall_set.ID]) == 0 {
					g.SyscallRuns[syscall_set.ID] = []prog.StaticEntry{ent}
				} else {
					g.SyscallRuns[syscall_set.ID] = append(g.SyscallRuns[syscall_set.ID], ent)
				}
			}
		}

		for s_set := range depinfo.Resource_Level {
			syscall_set := target.SyscallMap[s_set]
			g.ResourceRuns[syscall_set.ID] = make(map[string][]prog.StaticEntry)
			for s_ch, r_map := range depinfo.Resource_Level[s_set] {
				syscall_ch := target.SyscallMap[s_ch]
				cum_prob := 0
				g.ResourceRuns[syscall_set.ID][syscall_ch.Name] = make([]prog.StaticEntry, 0)
				res_deps := []ResultDep{}
				for key, prob := range r_map {
					// fill in g.ResourceRuns
					sp := strings.Split(key, "-")
					r_id1 := len(syscall_set.Args)
					if sp[0] != "x" && sp[0] != "r" {
						r_id1, _ = strconv.Atoi(sp[0])
					} else if sp[0] == "x" {
						r_id1 = find_res(syscall_set)
					}
					r_id2 := len(syscall_ch.Args)
					if sp[1] == "r" {
						res_deps = append(res_deps, ResultDep{Key: key, Prob: prob})
						continue
					} else if sp[1] != "x" && sp[1] != "r" {
						r_id2, _ = strconv.Atoi(sp[1])
					} else if sp[1] == "x" {
						r_id2 = find_res(syscall_ch)
					}
					ent := prog.StaticEntry{
						CumProb:       int(prob*1000000) + cum_prob,
						CheckerName:   s_ch,
						SetName:       s_set,
						ArgCheckIndex: r_id2,
						ArgSetIndex:   r_id1,
					}
					cum_prob += int(prob * 1000000)
					tmp := g.ResourceRuns[syscall_set.ID][syscall_ch.Name]
					tmp = append(tmp, ent)
					g.ResourceRuns[syscall_set.ID][syscall_ch.Name] = tmp
				}
				// add return value dependency to all arguments
				resource_args := get_res(syscall_ch)
				for _, res_dep := range res_deps {
					s_arg := len(syscall_set.Args)
					sp := strings.Split(res_dep.Key, "-")
					if sp[0] != "x" && sp[0] != "r" {
						s_arg, _ = strconv.Atoi(sp[0])
					} else if sp[0] == "x" {
						s_arg = find_res(syscall_set)
					}

					for _, c_arg := range resource_args {
						found := false
						cumprob := 0
						for _, ent := range g.ResourceRuns[syscall_set.ID][syscall_ch.Name] {
							if ent.CheckerName == s_ch && ent.SetName == s_set &&
								ent.ArgCheckIndex == c_arg &&
								ent.ArgSetIndex == s_arg {
								ent.CumProb += int(res_dep.Prob*1000000) / len(resource_args)
								found = true
							} else if found {
								ent.CumProb += int(res_dep.Prob*1000000) / len(resource_args)
							}
							cumprob = ent.CumProb
						}
						if !found {
							ent := prog.StaticEntry{
								CumProb:       int(res_dep.Prob*1000000)/len(resource_args) + cumprob,
								CheckerName:   s_ch,
								SetName:       s_set,
								ArgCheckIndex: c_arg,
								ArgSetIndex:   s_arg,
							}
							g.ResourceRuns[syscall_set.ID][syscall_ch.Name] = append(g.ResourceRuns[syscall_set.ID][syscall_ch.Name], ent)
						}
					}
				}
			}
		}
	*/

	return &g
}

func loadArgRunForward(path_args string, g *prog.StaticGraphChoiceTable, target *prog.Target) {
	// Fill in g.ArgRuns
	// This table is used to lookup dependencies based on a syscall and argument index.

	// read JSON file
	content, err := ioutil.ReadFile(path_args)
	if err != nil {
		// TODO change to just print error but continue fuzzing
		panic(fmt.Sprintf("failed to read depinfo.json: %v", err))
	}

	var depinfoArg ArgDepInfo
	err = json.Unmarshal(content, &depinfoArg)
	if err != nil {
		panic(fmt.Sprintf("failed to unmarshal depinfo.json: %v", err))
	}

	// fill in argsrun
	for s_ch := range depinfoArg {
		syscall_ch := target.SyscallMap[s_ch]
		g.ArgRuns[syscall_ch.ID] = make(map[int][]prog.StaticEntry)
		var ret_dep map[string]map[string]float64 = nil
		for ch_arg_str := range depinfoArg[s_ch] {
			var ch_arg int
			if ch_arg_str == "r" {
				ret_dep = depinfoArg[s_ch][ch_arg_str]
				continue
			} else if ch_arg_str == "x" {
				ch_arg = find_res(syscall_ch)
			} else {
				ch_arg, _ = strconv.Atoi(ch_arg_str)
			}
			g.ArgRuns[syscall_ch.ID][ch_arg] = make([]prog.StaticEntry, 0)
			cum_prob := 0
			for s_set, r_map := range depinfoArg[s_ch][ch_arg_str] {
				syscall_set := target.SyscallMap[s_set]

				has_ret := syscall_set.Ret != nil
				extra_prob := 0.0

				new_runs := make([]prog.StaticEntry, 0)
				for key, prob := range r_map {
					// fill in g.ArgRuns
					set_arg := len(syscall_set.Args)
					if key != "x" && key != "r" {
						set_arg, _ = strconv.Atoi(key)
					} else if key == "x" {
						set_arg = find_res(syscall_set)
					}

					if set_arg == len(syscall_set.Args) && !has_ret {
						// We need to distribute the probability of the return value to other entries
						extra_prob += prob
					} else {
						ent := prog.StaticEntry{
							CumProb:       int(prob*1000000) + cum_prob,
							Prob:          int(prob * 1000000),
							CheckerName:   s_ch,
							SetName:       s_set,
							ArgCheckIndex: ch_arg,
							ArgSetIndex:   set_arg,
						}
						cum_prob += int(prob * 1000000)
						new_runs = append(new_runs, ent)
					}
				}

				if extra_prob > 0 {
					// Distribute the probability of the return value to all other entries
					shift := 0
					for i := range new_runs {
						new_runs[i].Prob += int(extra_prob*1000000) / len(new_runs)
						new_runs[i].CumProb += int(extra_prob*1000000)/len(new_runs) + shift
						shift += int(extra_prob*1000000) / len(new_runs)
					}
				}

				g.ArgRuns[syscall_ch.ID][ch_arg] = append(g.ArgRuns[syscall_ch.ID][ch_arg], new_runs...)
			}
		}
		// add return value dependency to all arguments
		if ret_dep != nil {
			for s_set := range ret_dep {
				syscall_set := target.SyscallMap[s_set]
				resource_args := get_res(target.SyscallMap[s_ch])
				for _, ch_arg := range resource_args {
					for key, prob := range ret_dep[s_set] {
						// fill in g.ArgRuns
						set_arg := len(syscall_set.Args)
						if key != "x" && key != "r" {
							set_arg, _ = strconv.Atoi(key)
						} else if key == "x" {
							set_arg = find_res(syscall_set)
						}
						found := false
						cumprob := 0
						for _, ent := range g.ArgRuns[syscall_ch.ID][ch_arg] {
							if ent.CheckerName == s_ch && ent.SetName == s_set &&
								ent.ArgCheckIndex == ch_arg &&
								ent.ArgSetIndex == set_arg {
								ent.CumProb += int(prob*1000000) / len(resource_args)
								ent.Prob = int(prob*1000000) / len(resource_args)
								found = true
							} else if found {
								ent.CumProb += int(prob*1000000) / len(resource_args)
							}
							cumprob = ent.CumProb
						}
						if !found {
							ent := prog.StaticEntry{
								CumProb:       int(prob*1000000)/len(resource_args) + cumprob,
								Prob:          int(prob*1000000) / len(resource_args),
								CheckerName:   s_ch,
								SetName:       s_set,
								ArgCheckIndex: ch_arg,
								ArgSetIndex:   set_arg,
							}
							g.ArgRuns[syscall_ch.ID][ch_arg] = append(g.ArgRuns[syscall_ch.ID][ch_arg], ent)
						}
					}
				}
			}
		}
	}
}

func loadArgRunBackward(path_args string, g *prog.StaticGraphChoiceTable, target *prog.Target) {
	// Fill in g.ArgRuns
	// This table is used to lookup dependencies based on a syscall and argument index.

	// read JSON file
	content, err := ioutil.ReadFile(path_args)
	if err != nil {
		// TODO change to just print error but continue fuzzing
		panic(fmt.Sprintf("failed to read depinfo.json: %v", err))
	}

	var depinfoArg ArgDepInfo
	err = json.Unmarshal(content, &depinfoArg)
	if err != nil {
		panic(fmt.Sprintf("failed to unmarshal depinfo.json: %v", err))
	}

	// fill in argsrun
	for s_set := range depinfoArg {
		syscall_set := target.SyscallMap[s_set]
		g.ArgRuns[syscall_set.ID] = make(map[int][]prog.StaticEntry)
		for set_arg_str := range depinfoArg[s_set] {
			var set_arg int
			if set_arg_str == "r" {
				set_arg = len(syscall_set.Args)
			} else if set_arg_str == "x" {
				set_arg = find_res(syscall_set)
			} else {
				set_arg, _ = strconv.Atoi(set_arg_str)
			}
			g.ArgRuns[syscall_set.ID][set_arg] = make([]prog.StaticEntry, 0)
			cum_prob := 0
			for s_ch, r_map := range depinfoArg[s_set][set_arg_str] {
				syscall_ch := target.SyscallMap[s_ch]
				var ret_dep float64 = 0
				for key, prob := range r_map {
					// fill in g.ArgRuns
					ch_arg := len(syscall_ch.Args)
					if key == "r" {
						ret_dep = prob
						continue
					} else if key != "x" {
						ch_arg, _ = strconv.Atoi(key)
					} else if key == "x" {
						ch_arg = find_res(syscall_ch)
					}
					ent := prog.StaticEntry{
						CumProb:       int(prob*1000000) + cum_prob,
						Prob:          int(prob * 1000000),
						CheckerName:   s_ch,
						SetName:       s_set,
						ArgCheckIndex: ch_arg,
						ArgSetIndex:   set_arg,
					}
					cum_prob += int(prob * 1000000)
					tmp := g.ArgRuns[syscall_set.ID][set_arg]
					tmp = append(tmp, ent)
					g.ArgRuns[syscall_set.ID][set_arg] = tmp
				}

				if ret_dep != 0 {
					resource_args := get_res(target.SyscallMap[s_ch])
					for _, c_arg := range resource_args {
						found := false
						cumprob := 0
						for _, ent := range g.ArgRuns[syscall_set.ID][set_arg] {
							if ent.CheckerName == s_ch && ent.SetName == s_set &&
								ent.ArgCheckIndex == c_arg &&
								ent.ArgSetIndex == set_arg {
								ent.CumProb += int(ret_dep*1000000) / len(resource_args)
								ent.Prob += int(ret_dep*1000000) / len(resource_args)
								found = true
							} else if found {
								ent.CumProb += int(ret_dep*1000000) / len(resource_args)
							}
							cumprob = ent.CumProb
						}
						if !found {
							ent := prog.StaticEntry{
								CumProb:       int(ret_dep*1000000)/len(resource_args) + cumprob,
								Prob:          int(ret_dep*1000000) / len(resource_args),
								CheckerName:   s_ch,
								SetName:       s_set,
								ArgCheckIndex: c_arg,
								ArgSetIndex:   set_arg,
							}
							g.ArgRuns[syscall_set.ID][set_arg] = append(g.ArgRuns[syscall_set.ID][set_arg], ent)
						}
					}
				}
			}
		}
	}
}

func ParseDepInfo(workdir string, target *prog.Target) *prog.StaticGCT {
	static := prog.StaticGCT{}

	static.GCTForward = &prog.StaticGraphChoiceTable{
		//SyscallRuns:  make([][]prog.StaticEntry, len(target.Syscalls)),
		//ResourceRuns: make([]map[string][]prog.StaticEntry, len(target.Syscalls)),
		ArgRuns: make([]map[int][]prog.StaticEntry, len(target.Syscalls)),
	}
	//static.GCTForward = loadGraphChoiceTableForward(workdir+"/depinfo.json", target)
	loadArgRunForward(workdir+"/deps_args.json", static.GCTForward, target)
	static.GCTBackward = &prog.StaticGraphChoiceTable{
		//SyscallRuns:  make([][]prog.StaticEntry, len(target.Syscalls)),
		//ResourceRuns: make([]map[string][]prog.StaticEntry, len(target.Syscalls)),
		ArgRuns: make([]map[int][]prog.StaticEntry, len(target.Syscalls)),
	}
	//static.GCTBackward = loadGraphChoiceTableBackward(workdir+"/depinfo_backward.json", target)
	loadArgRunBackward(workdir+"/deps_args_backward.json", static.GCTBackward, target)

	return &static
}

func find_res(meta *prog.Syscall) int {
	for i, f := range meta.Args {
		if _, ok := f.Type.(*prog.ResourceType); ok {
			return i
		}
	}
	return len(meta.Args)
}

func get_res(meta *prog.Syscall) []int {
	res := make([]int, 0)
	for i, f := range meta.Args {
		if _, ok := f.Type.(*prog.ResourceType); ok {
			res = append(res, i)
		}
	}
	return res
}
