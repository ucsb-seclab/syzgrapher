package main

import (
	"os"
	"fmt"
	"strconv"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type Interface struct {
	Family      int
	SockType    int
	Protocol    int
	Constructor *prog.Syscall
	Calls       []*prog.Syscall
}

type InterfaceDr struct {
	Paths       []string
	Constructor *prog.Syscall
	Calls       []*prog.Syscall
}

func lessSpecific(a, b []string) bool {
	if len(a) >= len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func retrieve_interface(family, sock_type, protocol int, target *prog.Target) Interface {
	interf := Interface{
		Family:   family,
		SockType: sock_type,
		Protocol: protocol,
	}

	// retrieve constructor
	candidates := []*prog.Syscall{}
	for _, c := range target.Syscalls {
		if c.CallName == "socket" {
			// if the family is specific, it needs to match. Otherwise, it cannot
			// be specified by the syscall
			if family != -1 {
				if _, ok := c.Args[0].Type.(*prog.ConstType); !ok ||
					uint64(family) != c.Args[0].Type.(*prog.ConstType).Val {
					continue
				}
			}
			if family == -1 {
				if _, ok := c.Args[0].Type.(*prog.ConstType); ok {
					continue
				}
			}

			if sock_type != -1 {
				if _, ok := c.Args[1].Type.(*prog.ConstType); !ok ||
					uint64(sock_type) != c.Args[1].Type.(*prog.ConstType).Val {
					continue
				}
			}
			if sock_type == -1 {
				if _, ok := c.Args[1].Type.(*prog.ConstType); ok {
					continue
				}
			}

			// if the protocol is specified, it needs to match. Otherwise, it cannot
			// be specified by the syscall
			if protocol != -1 {
				if _, ok := c.Args[2].Type.(*prog.ConstType); !ok ||
					uint64(protocol) != c.Args[2].Type.(*prog.ConstType).Val {
					continue
				}
			}
			if protocol == -1 {
				if _, ok := c.Args[2].Type.(*prog.ConstType); ok {
					continue
				}
			}

			candidates = append(candidates, c)
		}
	}

	if len(candidates) == 0 {
		fmt.Printf("Error: no constructor found\n")
		os.Exit(1)
	} else if len(candidates) > 1 {
		fmt.Printf("Error: multiple constructors found\n")
		for _, c := range candidates {
			fmt.Printf("\t%v\n", c.Name)
		}
		os.Exit(1)
	}

	interf.Constructor = candidates[0]

	// retrieve calls
	thisSock := target.GetResourceDesc(interf.Constructor.Ret.Name())
	for _, c := range target.Syscalls {
		for _, inp := range c.GetInputResources(target) {
			if inp.Name == thisSock.Name || lessSpecific(inp.Kind, thisSock.Kind){
				interf.Calls = append(interf.Calls, c)
				break
			}
		}
	}

	return interf
}

func print_helper(calls []*prog.Syscall) string {
	ret := ""
	for _, c := range calls {
		ret += fmt.Sprintf("\t%v - ", c.Name)
		//fmt.Printf("\t%v - ", c.Name)
		for _, arg := range c.Args {
			if t, ok := arg.Type.(*prog.ConstType); ok {
				ret += fmt.Sprintf("%v ", t.Val)
				//fmt.Printf("%v ", t.Val)
			} else if _, ok := arg.Type.(*prog.ResourceType); ok {
				ret += fmt.Sprintf("r ")
				//fmt.Printf("r ")
			} else {
				ret += fmt.Sprintf("<> ")
				//fmt.Printf("<> ")
			}
		}
		if c.Ret != nil {
			ret += fmt.Sprintf("ret")
			//fmt.Printf("ret")
		}
		ret += fmt.Sprintf("\n")
		//fmt.Printf("\n")
	}
	return ret
}

func print_interface(interf Interface) {
	fmt.Printf("Family: %v\n", interf.Family)
	fmt.Printf("SockType: %v\n", interf.SockType)
	fmt.Printf("Protocol: %v\n", interf.Protocol)
	fmt.Printf("Constructor: %v\n", interf.Constructor.Name)
	fmt.Printf("Calls:\n")
	print(print_helper(interf.Calls))
	fmt.Printf("\n\n")
}

func print_interface_dr(dr InterfaceDr) string {
	inter := ""
	inter += fmt.Sprintf("Paths:\n")
	//fmt.Printf("Paths:\n")
	for _, p := range dr.Paths {
		inter += fmt.Sprintf("\t%v\n", p[:len(p)-1])
		//fmt.Printf("\t%v\n", p)
	}
	inter += fmt.Sprintf("Constructor: %v\n", dr.Constructor.Name)
	//fmt.Printf("Constructor: %v\n", dr.Constructor.Name)
	inter += fmt.Sprintf("Calls:\n")
	//fmt.Printf("Calls:\n")
	inter += print_helper(dr.Calls)
	//print(print_helper(dr.Calls))
	inter += fmt.Sprintf("\n\n")
	//fmt.Printf("\n\n")

	return inter 
}

func print_config(interf Interface) {
	fmt.Printf("\"enable_syscalls\": [\n")
	fmt.Printf("\t\"%v\",\n", interf.Constructor.Name)
	for _, c := range interf.Calls {
		fmt.Printf("\t\"%v\",\n", c.Name)
	}
	fmt.Printf("],\n")
}

func retrieve_all_interfaces(target *prog.Target) []Interface {
	interfaces := []Interface{}

	for _, c := range target.Syscalls {
		if c.CallName == "socket" {
			family := -1
			if _, ok := c.Args[0].Type.(*prog.ConstType); ok {
				family = int(c.Args[0].Type.(*prog.ConstType).Val)
			}
			sock_type := -1
			if family != -1 {
				if _, ok := c.Args[1].Type.(*prog.ConstType); ok {
					sock_type = int(c.Args[1].Type.(*prog.ConstType).Val)
				}
			}
			protocol := -1
			if family != -1 {
				if _, ok := c.Args[2].Type.(*prog.ConstType); ok {
					protocol = int(c.Args[2].Type.(*prog.ConstType).Val)
				}
			}

			interf := retrieve_interface(family, sock_type, protocol, target)

			interfaces = append(interfaces, interf)
		}
	}

	return interfaces
}

func handle_driver(c *prog.Syscall, target *prog.Target) InterfaceDr {
	dr := InterfaceDr{
		Constructor: c,
	}
	if ptr, ok := c.Args[1].Type.(*prog.PtrType); ok {
		dr.Paths = append(dr.Paths, ptr.Elem.(*prog.BufferType).Values...)

		// retrieve calls
		thisFile := target.GetResourceDesc(c.Ret.Name())
		for _, c := range target.Syscalls {
			for _, inp := range c.GetInputResources(target) {
				if inp.Name == thisFile.Name || lessSpecific(inp.Kind, thisFile.Kind){
					dr.Calls = append(dr.Calls, c)
					break
				}
			}
		}
	}

	return dr
}

func retrieve_drivers(target *prog.Target) {
	files := ""
	for _, c := range target.Syscalls {
		if c.CallName == "openat" {
			if ptr, ok := c.Args[1].Type.(*prog.PtrType); ok {
				for _, val := range ptr.Elem.(*prog.BufferType).Values {
					files = fmt.Sprintf("%v\n%v", files, val[:len(val)-1])
				}
			}
		}
	}

	err := os.WriteFile("driver_files.txt", []byte(files), 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	drivers := []InterfaceDr{}
	for _, c := range target.Syscalls {
		if c.CallName == "openat" {
			drivers = append(drivers, handle_driver(c, target))
		}
	}

	// print drivers
	inter := ""
	for _, dr := range drivers {
		inter = fmt.Sprintf("%v%v", inter, print_interface_dr(dr))
	}

	err = os.WriteFile("driver_interfaces.txt", []byte(inter), 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
}

func main() {
	if len(os.Args) != 3 && len(os.Args) != 6 {
		fmt.Printf("Usage: %v <os> <arch> [family sock_type protocol]\n", os.Args[0])
		os.Exit(1)
	}

	target, err := prog.GetTarget(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) == 6 {
		// convert all arguments to ints
		family, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		sock_type, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		protocol, err := strconv.Atoi(os.Args[5])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		interf := retrieve_interface(family, sock_type, protocol, target)

		//print_config(interf)
		print_interface(interf)
	} else {
		// retrieve all interfaces
		interfaces := retrieve_all_interfaces(target)

		for _, interf := range interfaces {
			print_interface(interf)
		}
	}

	retrieve_drivers(target)
}
