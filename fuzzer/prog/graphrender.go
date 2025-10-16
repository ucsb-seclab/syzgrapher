package prog

import (
	"fmt"
)

type GraphExportInfo struct {
	Nodes []GraphExportNode `json:"nodes"`
}

type GraphExportNode struct {
	Inputs  []GraphExportNodeInput  `json:"inputs"`
	Outputs []GraphExportNodeOutput `json:"outputs"`
	Meta    GraphExportNodeMeta     `json:"meta"`
}

type GraphExportNodeInput struct {
	NodeIdx  int    `json:"node_idx"`
	ConnIdx  int    `json:"conn_idx"`
	Resource string `json:"resource"`

	// Minimum resource required for this input
	// If there is a conflict, this will be ""
	MinResource string `json:"min_resource"`

	// True if the resource being passed in is a more general version of the
	// actual one we want.
	IsDowncast bool `json:"is_downcast"`

	// True if the resource being passed in is a more specific version of the
	// actual one we want.
	IsUpcast bool `json:"is_upcast"`

	IsAnycast bool `json:"is_anycast"`

	IsInvalid bool `json:"is_invalid"`
}

type GraphExportNodeOutput struct {
	NodeIdx     int    `json:"node_idx"`
	ConnIdx     int    `json:"conn_idx"`
	Resource    string `json:"resource"`
	MaxResource string `json:"max_resource"`
}

type GraphExportNodeMeta struct {
	Syscall     int    `json:"syscall"`
	SyscallName string `json:"syscall_name"`
}

func nodeLabel(g *GraphProg, node int) string {
	lbl := ""
	lbl += "<table border=\"0\" cellborder=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n"

	// Inputs
	lbl += "<tr><td border=\"0\"><table border=\"0\" cellborder=\"0\" cellspacing=\"0\" cellpadding=\"0\"><tr>\n"
	for i, input := range g.Nodes[node].Inputs {
		// Spacer
		lbl += "<td width=\"10\"></td>\n"

		// Input
		bgcolor := ""
		if input.NodeIdx < 0 {
			if input.NodeIdx == -3 {
				// Special value
				bgcolor = " bgcolor=\"pink\""
			} else {
				bgcolor = " bgcolor=\"red\""
			}
		}

		r := input.Resource.Type().Name()
		rm := g.MinimumInputRes(node, i)

		t := r
		if r != rm {
			t = fmt.Sprintf("%v (%v)", r, rm)
		}

		if rm == "" {
			bgcolor = " bgcolor=\"purple\""
			t = fmt.Sprintf("%v (!)", r)
		}

		lbl += fmt.Sprintf("<td port=\"in%v\" border=\"1\" cellpadding=\"1\"%v>%v</td>", i, bgcolor, t)
	}
	lbl += "<td width=\"10\"></td>\n"
	lbl += "</tr></table></td></tr>\n"

	// Syscall
	lbl += fmt.Sprintf("<tr><td border=\"1\" cellpadding=\"4\">[%v] %v</td></tr>\n", node, g.Nodes[node].Meta.Name)

	// Outputs
	lbl += "<tr><td border=\"0\"><table border=\"0\" cellborder=\"0\" cellspacing=\"0\" cellpadding=\"0\"><tr>\n"
	for i, output := range g.Nodes[node].Outputs {
		// Spacer
		lbl += "<td width=\"10\"></td>\n"

		// Output
		bgcolor := ""
		if output.NodeIdx < 0 {
			bgcolor = " bgcolor=\"red\""
		}

		r := output.Resource.Type().Name()
		rm := g.MaximumOutputRes(node, i)

		t := r
		if r != rm {
			t = fmt.Sprintf("%v (%v)", r, rm)
		}

		lbl += fmt.Sprintf("<td port=\"out%v\" border=\"1\" cellpadding=\"1\"%v>%v</td>", i, bgcolor, t)
	}
	lbl += "<td width=\"10\"></td>\n"
	lbl += "</tr></table></td></tr>\n"

	lbl += "</table>"

	return lbl
}

func (g *GraphProg) ToDOT() string {
	d := ""
	d += "digraph G {\nrankdir=TB\n"

	for i := range g.Nodes {
		d += fmt.Sprintf("node%d [shape=plaintext, label=<%v>]\n", i, nodeLabel(g, i))
	}

	for i := range g.Nodes {
		for j, input := range g.Nodes[i].Outputs {
			if input.NodeIdx >= 0 {
				d += fmt.Sprintf("node%d:out%d -> node%d:in%d\n", i, j, input.NodeIdx, input.ConnIdx)
			}
		}
	}

	d += "}\n"
	return d
}

func (g *GraphProg) Export() GraphExportInfo {
	info := GraphExportInfo{}

	for i := range g.Nodes {
		node := GraphExportNode{
			Meta: GraphExportNodeMeta{
				Syscall:     g.Nodes[i].Meta.ID,
				SyscallName: g.Nodes[i].Meta.Name,
			},
		}

		for j, input := range g.Nodes[i].Inputs {
			upcast, downcast, anycast, invalid := g.GetInputSpecificity(i, j)

			node.Inputs = append(node.Inputs, GraphExportNodeInput{
				NodeIdx:     input.NodeIdx,
				ConnIdx:     input.ConnIdx,
				Resource:    input.Resource.Type().Name(),
				MinResource: g.MinimumInputRes(i, j),
				IsUpcast:    upcast,
				IsDowncast:  downcast,
				IsAnycast:   anycast,
				IsInvalid:   invalid,
			})
		}

		for j, output := range g.Nodes[i].Outputs {
			node.Outputs = append(node.Outputs, GraphExportNodeOutput{
				NodeIdx:     output.NodeIdx,
				ConnIdx:     output.ConnIdx,
				Resource:    output.Resource.Type().Name(),
				MaxResource: g.MaximumOutputRes(i, j),
			})
		}

		info.Nodes = append(info.Nodes, node)
	}

	return info
}
