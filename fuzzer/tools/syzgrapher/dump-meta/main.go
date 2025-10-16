package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type ProgInfo struct {
	Program     []byte               `json:"program"`
	GraphInfo   prog.GraphExportInfo `json:"graph_info"`
	Origin      *prog.ProgOrigin     `json:"origin"`
	CreatedAt   int64                `json:"created_at"`
	SignalCalls []int                `json:"signal_calls"`
	SignalExtra bool                 `json:"signal_extra"`
}

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

func dumpDB(target *prog.Target, database string) {
	db, err := db.Open(database, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}

	var meta []ProgInfo = make([]ProgInfo, len(db.Records))

	idx := 0
	for _, rec := range db.Records {
		var entry rpctype.InputMeta
		buf := bytes.NewBuffer(rec.Val)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&entry); err != nil {
			fmt.Printf("Error while decoding meta: %v", err)
			os.Exit(1)
		}

		p, err := target.DeserializeNoValidation(entry.Prog)
		if err != nil {
			fmt.Printf("Error while deserializing program: %v", err)
			os.Exit(1)
		}

		graph := prog.ProgToGraph(p)
		info := ProgInfo{
			Program:     entry.Prog,
			GraphInfo:   graph.Export(),
			Origin:      entry.Origin,
			CreatedAt:   entry.CreatedAt,
			SignalCalls: entry.SignalCalls,
			SignalExtra: entry.SignalExtra,
		}
		meta[idx] = info

		idx++

		// print progress to stderr
		fmt.Fprintf(os.Stderr, "\r%d/%d", idx, len(db.Records))
	}

	json, err := json.Marshal(meta)
	if err != nil {
		fmt.Printf("Error while marshalling stats: %v", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", json)
}

func main() {
	var fDB = flag.String("db", "", "Path to meta.db file")
	var fOS = flag.String("os", "", "OS")
	var fArch = flag.String("arch", "", "Arch")
	flag.Parse()

	if *fOS == "" || *fArch == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, err := prog.GetTarget(*fOS, *fArch)
	if err != nil {
		fmt.Printf("Error while getting target: %v", err)
		os.Exit(1)
	}

	prog.RegisterAllOrigin()

	dumpDB(target, *fDB)
}
