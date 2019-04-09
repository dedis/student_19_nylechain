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



const startRedis = "startRedis"

// Name is the name of the service.
var Name = "Redis"
var PingName = "Ping"

// Service holds the state of the service.
type Service struct {
	*onet.ServiceProcessor
	// configures a set of rings that we are a part of
	// rings mapset.Set
	Nodes              LocalityNodes
	LocalityTree       *onet.Tree
	Parents            []*onet.TreeNode
	GraphTree          map[string][]GraphTree
	BinaryTree         map[string][]*onet.Tree
	alive              bool
	Distances          map[*LocalityNode]map[*LocalityNode]float64

}

const RND_NODES = false
const NR_LEVELS = 3
const OPTIMIZED = false
const OPTTYPE = 1
const MIN_BUNCH_SIZE = 39
const TREE_ID = 8

func (s *Service) Setup(ServerIdentityToName map[*network.ServerIdentity]string) {

	s.Nodes.ServerIdentityToName = make(map[network.ServerIdentityID]string)
	for k, v := range ServerIdentityToName {
		s.Nodes.ServerIdentityToName[k.ID] = v
	}
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
	s.GraphTree = make(map[string][]GraphTree)
	s.BinaryTree = make(map[string][]*onet.Tree)

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

func (s *Service)genTrees(RandomCoordsLevels bool, Levels int, Optimized bool, OptimisationLevel int, OptType int, pingDist map[string]map[string]float64) {

	// genTrees placeholder code, ideally we'll generate trees from small to large

	CreateLocalityGraph(s.Nodes, RandomCoordsLevels, RandomCoordsLevels, Levels, pingDist)
	myname := s.Nodes.GetServerIdentityToName(s.ServerIdentity())

	if Optimized {
		OptimizeGraph(s.Nodes, myname, OptimisationLevel, OptType)
	}

	//tree, NodesList, Parents, Distances := gentree.CreateOnetLPTree(s.Nodes, myname, OptimisationLevel)


	// route request to the roots of all rings i'm part of, using the distance oracles thingie


	// then everyone runs consensus in their trees



	dist2 := AproximateDistanceOracle(s.Nodes)

	// TODO we generate trees for all nodes
	for _, crtRoot := range s.Nodes.All {
		crtRootName := crtRoot.Name

		//log.LLvl1("root name = ", crtRootName)
		tree, NodesList, Parents := CreateOnetRings(s.Nodes, crtRootName, dist2)

		//log.Lvl1("done")

		// update distances only if i'm the root
		if crtRootName == myname {
			s.Distances = dist2

			log.Lvl1("CHECK that distances make sense")
			for src, m := range dist2 {
				for dst, dist := range m {
					log.Lvl2("comparing for", src.Name, "-", dst.Name, "physical dist", ComputeDist(src, dst, pingDist), "approx dist", dist)
					if dist > 5 * ComputeDist(src, dst, pingDist) {
						log.Lvl1("comparing for", src.Name, "-", dst.Name, "physical dist", ComputeDist(src, dst, pingDist), "approx dist", dist, "5x dist", 5 * ComputeDist(src, dst, pingDist))
						log.Lvl1("WOAAAAA way too long!!!")
					}
				}

			}

		}

		for i, n := range tree {
			s.GraphTree[crtRootName] = append(s.GraphTree[crtRootName], GraphTree{
				n,
				NodesList[i],
				Parents[i],
			})
		}
	}

	for rootName, graphTrees := range s.GraphTree {
		for _, n := range graphTrees {

			rosterNames := make([]string, 0)
			for _,si := range n.Tree.Roster.List {
				rosterNames = append(rosterNames, s.Nodes.GetServerIdentityToName(si))
			}

			log.LLvl1("generation node ", s.Nodes.GetServerIdentityToName(s.ServerIdentity()), "rootName x", rootName, "creates binary with roster", rosterNames)

			s.BinaryTree[rootName] = append(s.BinaryTree[rootName], s.CreateBinaryTreeFromGraphTree(n))
		}
	}
}




//Coumputes A Binary Tree Based On A Graph
func (s *Service) CreateBinaryTreeFromGraphTree(GraphTree GraphTree) *onet.Tree {

	BinaryTreeRoster := GraphTree.Tree.Roster
	Tree := BinaryTreeRoster.GenerateBinaryTree()

	return Tree
}

func (s *Service) Test(config *onet.SimulationConfig) {

	//config.Overlay.RegisterTree()

	s.ReadNodeInfo("somefile")

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


func (s *Service) InitializeMaps(config *onet.SimulationConfig) map[*network.ServerIdentity]string {

	s.Nodes.ServerIdentityToName = make(map[network.ServerIdentityID]string)
	ServerIdentityToName := make(map[*network.ServerIdentity]string)

	nextPortsAvailable := make(map[string]int)
	portIncrement := 1000

	// get machines

	for _, node := range config.Tree.List() {
		machineAddr := strings.Split(strings.Split(node.ServerIdentity.Address.String(), "//")[1], ":")[0]
		//log.LLvl1("machineaddr", machineAddr)
		log.Lvl2("node addr", node.ServerIdentity.Address.String())
		nextPortsAvailable[machineAddr] = 20000
	}





		for _, treeNode := range config.Tree.List() {
			for i := range s.Nodes.All {



				machineAddr := strings.Split(strings.Split(treeNode.ServerIdentity.Address.String(), "//")[1], ":")[0]
				if !s.Nodes.All[i].IP[machineAddr] {
					continue
				}


				if s.Nodes.All[i].ServerIdentity != nil {
					// current node already has stuff assigned to it, get the next free one
					continue
				}


				if treeNode.ServerIdentity != nil && treeNode.ServerIdentity.Address == ""{
					log.Error("nil 132132", s.Nodes.All[i].Name)
				}

				s.Nodes.All[i].ServerIdentity = treeNode.ServerIdentity
				s.Nodes.All[i].ServerIdentity.Address = treeNode.ServerIdentity.Address


				// set reserved ports
				s.Nodes.All[i].AvailablePortsStart = nextPortsAvailable[machineAddr]
				s.Nodes.All[i].AvailablePortsEnd = s.Nodes.All[i].AvailablePortsStart + portIncrement
				// fot all IP addresses of the machine set the ports!

				for k, v := range s.Nodes.All[i].IP {
					if v {
						nextPortsAvailable[k] = s.Nodes.All[i].AvailablePortsEnd
					}
				}

				s.Nodes.All[i].NextPort = s.Nodes.All[i].AvailablePortsStart
				// set names
				s.Nodes.ServerIdentityToName[treeNode.ServerIdentity.ID] = s.Nodes.All[i].Name
				ServerIdentityToName[treeNode.ServerIdentity] = s.Nodes.All[i].Name

				log.Lvl1("associating", treeNode.ServerIdentity.String(), "to", s.Nodes.All[i].Name, "ports", s.Nodes.All[i].AvailablePortsStart, s.Nodes.All[i].AvailablePortsEnd, s.Nodes.All[i].ServerIdentity.Address)

				break
			}

		}


	return ServerIdentityToName
}



func (s *Service) ReadNodeInfo(fileName string) {
	s.ReadNodesFromFile(fileName)
}


func (s *Service) ReadNodesFromFile(filename string) {
	s.Nodes.All = make([]*LocalityNode, 0)

	readLine,_ := ReadFileLineByLine(filename)

	lineNr := 0

	for true {
		line := readLine()
		//fmt.Println(line)
		if line == "" {
			//fmt.Println("end")
			break
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		tokens := strings.Split(line, " ")
		//coords := strings.Split(tokens[1], ",")

		//name, x_str, y_str, IP, level_str := tokens[0], coords[0], coords[1], tokens[2], tokens[3]
		//x, _ := strconv.ParseFloat(x_str, 64)
		//y, _ := strconv.ParseFloat(y_str, 64)
		name, IP, level_str := tokens[0], tokens[1], tokens[2]

		x := 0.0
		y := 0.0
		level, err := strconv.Atoi(level_str)

		if err != nil {
			log.Lvl1("Error", err)

		}

		//	log.Lvl1("reqd node level", name, level_str, "lvl", level)

		myNode := CreateNode(name, x, y, IP, level)
		s.Nodes.All = append(s.Nodes.All, myNode)

		// TODO hack!!!
		if lineNr > 45 {
			s.Nodes.All[lineNr].Level = s.Nodes.All[lineNr%45].Level
		}
		lineNr++

	}

	log.Lvlf1("our nodes are %v", s.Nodes.All)

}


func CreateNode(Name string, x float64, y float64, IP string, level int) *LocalityNode {
	var myNode LocalityNode

	myNode.X = x
	myNode.Y = y
	myNode.Name = Name
	myNode.IP = make(map[string]bool)

	tokens := strings.Split(IP, ",")
	for _, t := range tokens {
		myNode.IP[t] = true
	}

	myNode.Level = level
	myNode.ADist = make([]float64, 0)
	myNode.PDist = make([]string, 0)
	myNode.Cluster = make(map[string]bool)
	myNode.Bunch = make(map[string]bool)
	myNode.Rings = make([]string, 0)
	return &myNode
}

func ReadFileLineByLine(configFilePath string) (func() string, error) {
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

