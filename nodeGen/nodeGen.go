package main
import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"time"
)

type NodeSimple struct {
	Name string
	X float64
	Y float64
	Level int
}

type SortedNodes []NodeSimple


func genAndPrintNodesS(N int, SpaceMax int, K int) {

	var RndSrc *rand.Rand
	RndSrc = rand.New(rand.NewSource(time.Now().UnixNano()))
	nodes := make([]NodeSimple, N)

	// generate coordinates for the physical nodes
	for i := 0; i < N; i++ {
		nodes[i].Name = "node_"+strconv.Itoa(i)
		nodes[i].X = rand.Float64() * float64(SpaceMax)
		nodes[i].Y = rand.Float64() * float64(SpaceMax)
	}

	prob := 1.0 / math.Pow(float64(N), 1.0/float64(K))

	for lvl := 0; lvl < K; lvl++ {
		for i := 0; i < N; i++ {
			if nodes[i].Level == lvl - 1 {
				rnd := RndSrc.Float64()
				if rnd < prob {
					nodes[i].Level = lvl
				}
			}
		}
	}

	// arrange nodes by x coordinate
	sort.Sort(SortedNodes(nodes[:N]))

	// rename for ease of stuff
	for i := 0; i < N; i++ {
		nodes[i].Name = "node_"+strconv.Itoa(i)
	}


	file, _ := os.Create("nodes.txt")
	defer file.Close()
	w := bufio.NewWriter(file)

	// print nodes in the out experiment file
	for i := 0 ; i < N ; i++ {
		xFloat := fmt.Sprintf("%f", nodes[i].X)
		yFloat := fmt.Sprintf("%f", nodes[i].Y)

		w.WriteString(nodes[i].Name + " " + xFloat + "," + yFloat + " " + strconv.Itoa(nodes[i].Level) + "\n")
	}

	w.Flush()
}

func (s SortedNodes) Len() int {
	return len(s)
}
func (s SortedNodes) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortedNodes) Less(i, j int) bool {
	return s[i].X < s[j].X
}


func main() {

	K := flag.Int("K", 3, "Number of levels.")
	N := flag.Int("N", 45, "Number of nodes.")
	SpaceMax := flag.Int("SpaceMax", 300, "Coordinate space size.")

	flag.Parse()

	genAndPrintNodesS(*N, *SpaceMax, *K)
}
