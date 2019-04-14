package gentree

import (
	"bufio"
	"fmt"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)


type LocalityContext struct {
	Nodes              LocalityNodes
	// keys are node names, values are a slice of graph trees
	graphTree 			map[string][]GraphTree
	// keys are node names, values are a slice of onet trees that are locality preserving
	LocalityTrees        map[string][]*onet.Tree
}


type GraphTree struct {
	Tree        *onet.Tree
	ListOfNodes []*onet.TreeNode
	Parents     map[*onet.TreeNode][]*onet.TreeNode
}

const RND_NODES = false
const NR_LEVELS = 3
const OPTIMIZED = false
const OPTTYPE = 1
const MIN_BUNCH_SIZE = 39

func (s *LocalityContext) Setup(roster *onet.Roster, nodesFile string) {

	s.readNodesFromFile(nodesFile)

	for _, myNode := range s.Nodes.All {
		myNode.ADist = make([]float64, 0)
		myNode.PDist = make([]string, 0)
		myNode.OptimalCluster = make(map[string]bool)
		myNode.OptimalBunch = make(map[string]bool)
		myNode.Cluster = make(map[string]bool)
		myNode.Bunch = make(map[string]bool)
		myNode.Rings = make([]string, 0)

	}
	// order nodesin s.Nodes in the order of index
	nodes := make([]*LocalityNode, len(s.Nodes.All))
	for _, n := range s.Nodes.All {
		nodes[NodeNameToInt(n.Name)] = n
	}
	s.Nodes.All = nodes
	s.Nodes.ClusterBunchDistances = make(map[*LocalityNode]map[*LocalityNode]float64)
	s.Nodes.Links = make(map[*LocalityNode]map[*LocalityNode]map[*LocalityNode]bool)
	s.graphTree = make(map[string][]GraphTree)
	s.LocalityTrees = make(map[string][]*onet.Tree)

	s.Nodes.ServerIdentityToName = make(map[network.ServerIdentityID]string)

	s.initializeServerToNodeMap(roster)


	// allocate distances
	for _, node := range s.Nodes.All {
		s.Nodes.ClusterBunchDistances[node] = make(map[*LocalityNode]float64)
		s.Nodes.Links[node] = make(map[*LocalityNode]map[*LocalityNode]bool)
		for _, node2 := range s.Nodes.All {
			s.Nodes.ClusterBunchDistances[node][node2] = math.MaxFloat64
			s.Nodes.Links[node][node2] = make(map[*LocalityNode]bool)

			if node == node2 {
				s.Nodes.ClusterBunchDistances[node][node2] = 0
			}
		}
	}


	// just emmptry pings for now
	pings := make(map[string]map[string]float64)
	s.genTrees(RND_NODES, NR_LEVELS, OPTIMIZED, MIN_BUNCH_SIZE, OPTTYPE, pings)
}

func (s *LocalityContext)genTrees(RandomCoordsLevels bool, Levels int, Optimized bool, OptimisationLevel int, OptType int, pingDist map[string]map[string]float64) {

	// genTrees placeholder code, ideally we'll generate trees from small to large
	CreateLocalityGraph(s.Nodes, RandomCoordsLevels, RandomCoordsLevels, Levels, pingDist)

	dist2 := AproximateDistanceOracle(s.Nodes)

	// we generate trees for all nodes
	for _, crtRoot := range s.Nodes.All {
		crtRootName := crtRoot.Name

		tree, NodesList, Parents := CreateOnetRings(s.Nodes, crtRootName, dist2)

		// update distances only if i'm the root

		log.Lvl2("CHECK that distances make sense")
		for src, m := range dist2 {
			for dst, dist := range m {
				log.Lvl2("comparing for", src.Name, "-", dst.Name, "physical dist", ComputeDist(src, dst, pingDist), "approx dist", dist)
				if dist > 5 * ComputeDist(src, dst, pingDist) {
					log.Lvl2("comparing for", src.Name, "-", dst.Name, "physical dist", ComputeDist(src, dst, pingDist), "approx dist", dist, "5x dist", 5 * ComputeDist(src, dst, pingDist))
					log.Lvl2("way too long!!!")
			}
			}
			}


		for i, n := range tree {
			s.graphTree[crtRootName] = append(s.graphTree[crtRootName], GraphTree{
				n,
				NodesList[i],
				Parents[i],
			})
		}
	}

	for rootName, graphTrees := range s.graphTree {
		for _, n := range graphTrees {

			rosterNames := make([]string, 0)
			for _,si := range n.Tree.Roster.List {
				rosterNames = append(rosterNames, s.Nodes.GetServerIdentityToName(si))
			}

			//log.LLvl1("rootName x", rootName, "creates binary with roster", rosterNames)

			s.LocalityTrees[rootName] = append(s.LocalityTrees[rootName], s.createBinaryTreeFromGraphTree(n))
		}
	}
}




//Coumputes A Binary Tree Based On A Graph
func (s *LocalityContext) createBinaryTreeFromGraphTree(GraphTree GraphTree) *onet.Tree {

	BinaryTreeRoster := GraphTree.Tree.Roster
	Tree := BinaryTreeRoster.GenerateBinaryTree()

	return Tree
}

/*
func (s *Service) Test(config *onet.SimulationConfig) {

	//config.Overlay.RegisterTree()

	s.ReadNodeInfo("example.txt")

	mymap := s.InitializeMaps(config)
	//mymap := s.InitializeMaps(config, false)

	s.Setup(mymap)


	registeredRosterIds := make([]string, 0)
	nrTrees := 0
	for _, trees := range s.BinaryTree {
		for _, tree := range trees {
			config.Overlay.RegisterTree(tree)
			registeredRosterIds = append(registeredRosterIds, tree.Roster.ID.String())
			nrTrees++
		}
	}


}
*/


func (s *LocalityContext) initializeServerToNodeMap(roster *onet.Roster) {
	if len(roster.List) != len(s.Nodes.All) {
		log.Panic("Roster has different length than the nr of nodes read from the file")
	}

	for i, rosterNode := range roster.List {
		s.Nodes.All[i].ServerIdentity = rosterNode
		s.Nodes.All[i].ServerIdentity.Address = rosterNode.Address
		s.Nodes.ServerIdentityToName[rosterNode.ID] = s.Nodes.All[i].Name
	}
}



func (s *LocalityContext) readNodesFromFile(filename string) {
	s.Nodes.All = make([]*LocalityNode, 0)

	readLine,_ := readFileLineByLine(filename)
	lineNr := 0

	for true {
		line := readLine()
		if line == "" {
			break
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		tokens := strings.Split(line, " ")
		coords := strings.Split(tokens[1], ",")
		x,y := coords[0], coords[1]
		name, level_str := tokens[0], tokens[2]

		level, err := strconv.Atoi(level_str)
		if err != nil {
			log.Lvl1("Error", err)
		}
		xFloat, err := strconv.ParseFloat(x, 64)
		if err != nil {
			log.Fatal("Problem when parsing pings")
		}
		yFloat, err := strconv.ParseFloat(y, 64)
		if err != nil {
			log.Fatal("Problem when parsing pings")
		}

		myNode := createNode(name, xFloat, yFloat, level)
		s.Nodes.All = append(s.Nodes.All, myNode)

		lineNr++
	}

	log.LLvl2("Read nodes", s.Nodes.All)
}


func createNode(Name string, x float64, y float64, level int) *LocalityNode {
	var myNode LocalityNode

	myNode.X = x
	myNode.Y = y
	myNode.Name = Name
	myNode.Level = level
	myNode.ADist = make([]float64, 0)
	myNode.PDist = make([]string, 0)
	myNode.Cluster = make(map[string]bool)
	myNode.Bunch = make(map[string]bool)
	myNode.Rings = make([]string, 0)

	return &myNode
}


func readFileLineByLine(configFilePath string) (func() string, error) {
	f, err := os.Open(configFilePath)
	//defer close(f)

	if err != nil {
		return func() string {return ""}, err
	}
	checkErr(err)
	reader := bufio.NewReader(f)
	//defer close(reader)
	var line string
	return func() string {
		if err == io.EOF {
			return ""
		}
		line, err = reader.ReadString('\n')
		checkErr(err)
		line = strings.Split(line, "\n")[0]
		return line
	}, nil
}


func checkErr(e error) {
	if e != nil && e != io.EOF {
		fmt.Print(e)
		panic(e)
	}
}

