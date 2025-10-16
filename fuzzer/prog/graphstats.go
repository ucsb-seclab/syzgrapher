package prog

type ProgStats struct {
	/// Number of nodes in the graph
	NumNodes int

	/// Number of complete edges in the graph
	/// Equivalent to number of reused resources
	NumEdges int

	/// Number of isolated graphs in the program (no chain of shared resources)
	NumIsolatedGraphs int

	/// Size of the largest isolated graph
	LargestIsolatedGraph int

	/// Length of the longest resource chain
	LongestResourceChain int

	/// (optional) Original program string
	OriginalProgram []byte
}

func numNodes(g *GraphProg) int {
	return len(g.Nodes)
}

func numEdges(g *GraphProg) int {
	count := 0
	for _, node := range g.Nodes {
		for _, output := range node.Outputs {
			if output.NodeIdx >= 0 {
				count++
			}
		}
	}
	return count
}

func visitMetrics(g *GraphProg) (int, int, int) {
	numIsolatedGraphs := 0
	largestIsolatedGraph := 0
	longestResourceChain := 0

	visited := make([]bool, len(g.Nodes))
	innerCount := 0

	/// Marks all connected nodes as visited
	var visit func(nodeIdx int, minDepth int, maxDepth int)
	visit = func(nodeIdx int, minDepth int, maxDepth int) {
		if visited[nodeIdx] {
			return
		}
		visited[nodeIdx] = true
		innerCount++
		if innerCount > largestIsolatedGraph {
			largestIsolatedGraph = innerCount
		}

		if minDepth+maxDepth > longestResourceChain {
			longestResourceChain = minDepth + maxDepth
		}

		for _, input := range g.Nodes[nodeIdx].Inputs {
			if input.NodeIdx >= 0 {
				visit(input.NodeIdx, minDepth+1, maxDepth)
			}
		}
		for _, output := range g.Nodes[nodeIdx].Outputs {
			if output.NodeIdx >= 0 {
				visit(output.NodeIdx, minDepth, maxDepth+1)
			}
		}
	}

	for {
		/// Find first unvisited node
		var nodeIdx int = -1
		for i, visited := range visited {
			if !visited {
				nodeIdx = i
				break
			}
		}
		if nodeIdx == -1 {
			break
		}
		innerCount = 0
		visit(nodeIdx, 0, 0)
		numIsolatedGraphs++
	}

	return numIsolatedGraphs, largestIsolatedGraph, longestResourceChain
}

func (g *GraphProg) ComputeStats() ProgStats {
	numIsolatedGraphs, largestIsolatedGraph, longestResourceChain := visitMetrics(g)
	return ProgStats{
		NumNodes:             numNodes(g),
		NumEdges:             numEdges(g),
		NumIsolatedGraphs:    numIsolatedGraphs,
		LargestIsolatedGraph: largestIsolatedGraph,
		LongestResourceChain: longestResourceChain,
	}
}
