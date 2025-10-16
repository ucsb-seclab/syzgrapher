package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	var fProgram = flag.String("program", "", "Path to program file (stdin if empty))")
	var fOut = flag.String("out", "", "Path to output file (stdout if empty)")

	var fOS = flag.String("os", "", "OS")
	var fArch = flag.String("arch", "", "Arch")
	flag.Parse()

	if *fOS == "" || *fArch == "" {
		flag.Usage()
		os.Exit(1)
	}

	var data []byte

	if *fProgram == "" {
		var err error
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Error while reading program: %v", err)
			os.Exit(1)
		}
	} else {
		var err error
		data, err = os.ReadFile(*fProgram)
		if err != nil {
			fmt.Printf("Error while reading program: %v", err)
			os.Exit(1)
		}
	}

	target, err := prog.GetTarget(*fOS, *fArch)
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		fmt.Printf("Error while deserializing program: %v", err)
		os.Exit(1)
	}

	graph := prog.ProgToGraph(p)
	dot := graph.ToDOT()

	if *fOut == "" {
		fmt.Printf("%s\n", dot)
		os.Exit(0)
	}

	f, err := os.Create(*fOut)
	if err != nil {
		fmt.Printf("Error while creating file: %v", err)
		os.Exit(1)
	}
	defer f.Close()

	_, err = f.WriteString(dot)
	if err != nil {
		fmt.Printf("Error while writing to file: %v", err)
		os.Exit(1)
	}
}
