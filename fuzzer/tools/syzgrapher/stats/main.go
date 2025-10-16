package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func progStats(target *prog.Target, program string) {
	data, err := os.ReadFile(program)
	if err != nil {
		fmt.Printf("Error while reading program: %v", err)
		os.Exit(1)
	}

	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		fmt.Printf("Error while deserializing program: %v", err)
		os.Exit(1)
	}

	graph := prog.ProgToGraph(p)
	stats := graph.ComputeStats()
	stats.OriginalProgram = data

	json, err := json.Marshal(stats)
	if err != nil {
		fmt.Printf("Error while marshalling stats: %v", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", json)
}

func dbStats(target *prog.Target, database string) {
	db, err := db.Open(database, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}

	var stats []prog.ProgStats = make([]prog.ProgStats, len(db.Records))

	idx := 0
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize: %v\n%s", err, rec.Val)
		}

		graph := prog.ProgToGraph(p)
		stats[idx] = graph.ComputeStats()
		stats[idx].OriginalProgram = rec.Val
		idx++
	}

	json, err := json.Marshal(stats)
	if err != nil {
		fmt.Printf("Error while marshalling stats: %v", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", json)
}

func main() {
	var fProgram = flag.String("program", "", "Path to program file")
	var fDB = flag.String("db", "", "Path to database file")
	var fOS = flag.String("os", "", "OS")
	var fArch = flag.String("arch", "", "Arch")
	flag.Parse()

	if *fOS == "" || *fArch == "" {
		flag.Usage()
		os.Exit(1)
	}
	if (*fProgram == "") == (*fDB == "") {
		fmt.Printf("Please specify either program or db file\n")
		flag.Usage()
		os.Exit(1)
	}

	target, err := prog.GetTarget(*fOS, *fArch)
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	if *fProgram != "" {
		progStats(target, *fProgram)
	} else {
		dbStats(target, *fDB)
	}
}
