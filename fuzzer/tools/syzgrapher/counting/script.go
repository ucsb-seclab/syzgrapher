package main

import (
	"os"
	"fmt"
	"sort"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type Elem struct {
	Name string
	Count int
}


func recTraversal(t prog.Type, seen map[prog.Type]bool) int {
	if seen[t] {
		return 0
	}
	seen[t] = true
	res := 0
	switch t.(type) {
	case *prog.ResourceType:
		res = 1
	case *prog.PtrType:
		res = recTraversal(t.(*prog.PtrType).Elem, seen)
	case *prog.ArrayType:
		res = recTraversal(t.(*prog.ArrayType).Elem, seen)
		res *= int(t.(*prog.ArrayType).RangeEnd)
	case *prog.StructType:
		for _, f := range t.(*prog.StructType).Fields {
			res += recTraversal(f.Type, seen)
		}
	case *prog.UnionType:
		for _, f := range t.(*prog.UnionType).Fields {
			r := recTraversal(f.Type, seen)
			if r > res {
				res = r
			}
		}
	}
	return res
}

func countResources(c *prog.Syscall) int {
	res := 0
	for _, f := range c.Args {
		res += recTraversal(f.Type, make(map[prog.Type]bool))
	}
	return res
}

func calcStatistics(target *prog.Target) {
	maxRes := 0
	maxName := ""
	sumRes := 0
	nums := make([]Elem, 0)
	dist := make(map[int]int)
	nonOne := 0
	adjust := 0

	for _, c := range target.Syscalls {
		if len(c.Name) >= 4 && c.Name[:3] == "syz" {
			adjust++
			continue
		}
		res := countResources(c)
		if res > maxRes {
			maxRes = res
			maxName = c.Name
		}
		sumRes += res
		nums = append(nums, Elem{c.Name, res})
		if res > 1 {
			nonOne++
		}
		dist[res]++
	}

	sort.Slice(nums, func(i, j int) bool {
		return nums[i].Count > nums[j].Count
	})

	fmt.Printf("Max resources: %v - %v\n", maxName, maxRes)
	fmt.Printf("Average resources: %v\n", float64(sumRes) / float64(len(target.Syscalls)-adjust))
	fmt.Printf("Non-one resources: %v/%v\n", nonOne, (len(target.Syscalls)-adjust))
	fmt.Printf("Distribution:\n")
	for k, v := range dist {
		fmt.Printf("%v: %v\n", k, v)
	}
	for _, e := range nums {
		fmt.Printf("%v: %v\n", e.Name, e.Count)
	}
}

func calcToplevelStatistics(target *prog.Target) {
	maxRes := 0
	maxName := ""
	sumRes := 0
	nums := make([]Elem, 0)
	dist := make(map[int]int)
	nonOne := 0
	adjust := 0

	for _, c := range target.Syscalls {
		if len(c.Name) >= 4 && c.Name[:3] == "syz" {
			adjust++
			continue
		}
		res := 0
		for _, f := range c.Args {
			if _, ok := f.Type.(*prog.ResourceType); ok {
				res++
			}
		}
		
		if _, ok := c.Ret.(*prog.ResourceType); ok {
			res++
		}
		
		if res > maxRes {
			maxRes = res
			maxName = c.Name
		}
		sumRes += res
		nums = append(nums, Elem{c.Name, res})
		if res > 1 {
			nonOne++
		}
		dist[res]++
	}

	sort.Slice(nums, func(i, j int) bool {
		return nums[i].Count > nums[j].Count
	})

	fmt.Printf("Max resources: %v - %v\n", maxName, maxRes)
	fmt.Printf("Average resources: %v\n", float64(sumRes) / float64(len(target.Syscalls)-adjust))
	fmt.Printf("Non-one resources: %v/%v\n", nonOne, (len(target.Syscalls)-adjust))
	fmt.Printf("Distribution:\n")
	for k, v := range dist {
		fmt.Printf("%v: %v\n", k, v)
	}
	for _, e := range nums {
		fmt.Printf("%v: %v\n", e.Name, e.Count)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %v <os> <arch> [t/c]\n", os.Args[0])
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if os.Args[3] == "t" {
		calcToplevelStatistics(target)
	} else {
		calcStatistics(target)
	}
}
