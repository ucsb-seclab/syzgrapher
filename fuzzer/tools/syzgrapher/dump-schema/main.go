package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/syzkaller/prog"
)

func main() {

	schema_path := os.Args[1]

	var schema prog.TargetSchema
	content, err := ioutil.ReadFile(schema_path)
	if err != nil {
		log.Fatalf("failed to read schema file: %v", err)
		os.Exit(1)
	} else {
		dec := gob.NewDecoder(bytes.NewBuffer(content))

		err = dec.Decode(&schema)
		if err != nil {
			log.Fatalf("failed to decode schema: %v", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Signatures: %v\n", len(schema.Signatures))
	fmt.Printf("base resource nodes: %v\n", len(schema.ResourceNodes))

	for k, v := range schema.ResourceNodes {
		fmt.Printf("Resource node: %v -> %v\n", k, len(v.Children))
	}
}
