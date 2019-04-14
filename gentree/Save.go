package gentree

import (
	"math"

	"gopkg.in/dedis/onet.v2/log"
)

//Removes a link from The LinkLlist
func RemoveLink(A *LocalityNode, B *LocalityNode, LinkList *map[*LocalityNode]map[*LocalityNode]bool) {

	(*LinkList)[A][B] = false
	(*LinkList)[B][A] = false
}

func UpdateDistance(all LocalityNodes, startNode *LocalityNode) {

	visited := make(map[string]bool)

	nodesVisited := 0

	nodesToVisit := 0
	for _, node := range all.All {
		if startNode.Cluster[node.Name] || startNode.Bunch[node.Name] {
			nodesToVisit++
		}
	}

	crtNode := startNode
	distSoFar := 0.0

	alreadyKnown := 0
	for _, node := range all.All {
		if all.ClusterBunchDistances[startNode][node] < math.MaxFloat64 {
			alreadyKnown++
		}
	}

	log.LLvl1("alreadyknown", alreadyKnown)

	if alreadyKnown == nodesToVisit {
		return
	}

	for nodesVisited < nodesToVisit {

		//log.LLvl1("nodes Visited", nodesVisited, "to visit", nodesToVisit)

		for _, node := range all.All {
			if all.ClusterBunchDistances[crtNode][node] < math.MaxFloat64 {
				//log.LLvl1("looking at link", crtNode.Name, node.Name)
				if distSoFar + all.ClusterBunchDistances[crtNode][node] < all.ClusterBunchDistances[startNode][node] {
					all.ClusterBunchDistances[startNode][node] = distSoFar + all.ClusterBunchDistances[crtNode][node]
					all.ClusterBunchDistances[node][startNode] = all.ClusterBunchDistances[startNode][node]
					all.Links[startNode][node][crtNode] = true
					//log.LLvl1("~~~~~~~~~~~~~~~relaxing", node.Name, "with dist", all.ClusterBunchDistances[startNode][node])
				}

			}
		}

		var nextNode *LocalityNode
		dist := math.MaxFloat64

		for reachableNode, reachableDist := range all.ClusterBunchDistances[startNode] {
			if !visited[reachableNode.Name] && reachableDist < dist {
				//log.LLvl1("candidate", reachableNode.Name, "with dist", reachableDist)
				nextNode = reachableNode
				dist = reachableDist
			}
		}
		if nextNode == nil {
			log.Error("nil!")

		} else {
			//log.LLvl1("--------------visiting", nextNode.Name, dist)
			visited[nextNode.Name] = true
			distSoFar = dist
		}

		if startNode.Bunch[nextNode.Name] || startNode.Cluster[nextNode.Name] {
			nodesVisited++
		}

		crtNode = nextNode

	}

}

//Removes Links from the Graph According to some omtimisation conditions
func RemoveLinks(all LocalityNodes, Root *LocalityNode, max int, OptType int) {

	Bridges := GetBridges(all, Root)

	/*
	_, _, Links := AproximateDistanceOracle(all)

	for _, node_a := range all.All {
		for _, node_b := range all.All {
			for w, exists := range Links[node_a][node_b] {
				if exists {
					log.LLvl1(node_a.Name, node_b.Name, "through", w.Name)
				}
			}
		}
	}
	*/


	// Range through all nodes and see what we can remove from their bunch - > but don't remove it!

	//TODO range is order


	for _, node_a := range all.All {

		log.LLvl1("optimizing node", node_a.Name)

		nredges := 0
		if OptType == 1 {
			nredges = 0
			for _, node := range all.All {
				if node_a.Cluster[node.Name] || node_a.Bunch[node.Name] {
					nredges++
				}
			}
		} else {
			nredges = MapLen2(node_a.OptimalBunch)
		}
		log.LLvl1("nr edges", nredges)

		/*
		nredgesBunch := MapLen2(node_a.Bunch)
		if nredges != nredgesBunch {
			log.Error("bunch size differs!")
		}
		*/

		// count the number of nodes in the bunch at each level
		nrPerLevel := make(map[int]map[string]bool)

		nrPerLevel[0] = make(map[string]bool)
		nrPerLevel[1] = make(map[string]bool)
		nrPerLevel[2] = make(map[string]bool)

		for Node, NodeExists := range node_a.OptimalBunch {

			if NodeExists {
				//Puts each node in its corresponding level
				nrPerLevel[all.GetByName(Node).Level][Node] = true

			}
		}

		//log.LLvl1("nrperlvl", nrPerLevel)

		//log.LLvl1("PDist", node_a.PDist)

		//The nodes of the PriorityLevel will be the ones that are prioritized when it comes to removing nodes
		PriorityLevel := len(all.All[0].PDist)

		if OptType == 1 {
			ClusterPriority := -1

			log.LLvl1("Cluster Opt")


			for nredges > max {

				//log.LLvl1("priority", PriorityLevel)
				//log.LLvl1(nrPerLevel)


				ClusterPriority += 1

				// TODO range in order
				//for ClusterNodeName, NodeExists := range node_a.OptimalCluster {
				for _, ClusterNode := range all.All {
					if node_a.OptimalCluster[ClusterNode.Name] {

						if ClusterNode.Level != ClusterPriority {
							continue
						}



						// try removing that cluster node
						// it'll affect the bunch of another node -> see if it breaks

						IsInPDist := false

						for _, NodeInPDist := range ClusterNode.PDist {

							if NodeInPDist == node_a.Name {

								IsInPDist = true

								break
							}
						}

						// too restritive!
						/*
						for _, linkNodes := range Links[ClusterNode] {

							linksize := 0
							for _, exists := range linkNodes {
								if exists {
									linksize++
								}
							}

							if linkNodes[node_a] && linksize == 1 {

								log.LLvl1("cannot remove", node_a.Name, "from bunch of", ClusterNode.Name)

								IsInPDist = true

								break
							}
						}
						*/

						//Removes nodes that can not be removed from the map where nodes are organized by levels
						if IsInPDist || ClusterNode == node_a || Bridges[node_a][ClusterNode] {

							// cannot remove node
							continue
						}

						// we can remove the node, let's do it
						node_a.OptimalCluster[ClusterNode.Name] = false

						//Does the inverse
						ClusterNode.OptimalBunch[node_a.Name] = false

						//Updates the Bridges
						Bridges = GetBridges(all, Root)

						// No more direct distance
						all.ClusterBunchDistances[node_a][ClusterNode] = math.MaxFloat64
						all.ClusterBunchDistances[ClusterNode][node_a] = math.MaxFloat64

						nredges--

						if nredges <= max {
							break
						}
					}

				}

				if nredges <= max {
					break
				}

				if ClusterPriority > len(all.All[0].PDist) {
					break
				}

			}

			log.LLvl1("nrEdges", nredges)
			log.LLvl1("cluster priority", ClusterPriority)

		}

		log.LLvl1("BUnch OPt")

		attempts := 0
		for nredges > max && attempts < 100 {
			attempts++
			//for Node, NodeExists := range node_a.OptimalBunch {
			log.LLvl1("going here", attempts)
			for _, NodeX := range all.All {
				if node_a.OptimalBunch[NodeX.Name] {

					node_b := all.GetByName(NodeX.Name)
					Node := NodeX.Name
					IsInPDist := false

					for _, NodeInPDist := range node_a.PDist {

						if NodeInPDist == Node {

							IsInPDist = true

							break
						}
					}

					//Removes nodes that can not be removed from the map where nodes are organized by levels
					if IsInPDist || node_b == node_a || Bridges[node_a][node_b] {

						nrPerLevel[node_b.Level][node_b.Name] = false

						continue
					}

					//Decreases the priority Level when it has removed all nodes in that level
					if MapLen2(nrPerLevel[PriorityLevel]) == 0 {

						PriorityLevel--
					}

					//Continues if the node that is about to be removed is not on the priority level
					if node_b.Level != PriorityLevel {

						continue

					}

					//Removes the node from the levels map
					nrPerLevel[PriorityLevel][node_b.Name] = false
					//Removes the node from the Bunch
					node_a.OptimalBunch[Node] = false
					//Does the inverse
					all.GetByName(Node).OptimalCluster[node_a.Name] = false

					// mark that there is no more direct link
					all.ClusterBunchDistances[node_a][node_b] = math.MaxFloat64
					all.ClusterBunchDistances[node_b][node_a] = math.MaxFloat64

					//Updates the Bridges
					Bridges = GetBridges(all, Root)
					//Decreases the amount of edges
					nredges--
					break

				}
			}

		}
		log.LLvl1("nrEdges", nredges)
		log.LLvl1("optimizing node", node_a.Name, "DONE")

		// update the distance to the cluster and the bunch

		UpdateDistance(all, node_a)


	}

}

//Does the same as MapLen but with maps that have the type String as keys
//The Length will be the amount of keys that have the value "true"
func MapLen2(Map map[string]bool) int {

	i := 0

	for _, v := range Map {

		if v {
			i++
		}

	}

	return i
}

//Returns the Union of the Bunch and The Cluster with no duplicates
func GetChildren(all LocalityNodes, A *LocalityNode) map[*LocalityNode]bool {

	Children := make(map[*LocalityNode]bool)

	for n, ok := range A.OptimalBunch {

		if ok {
			Children[all.GetByName(n)] = true

		}
	}

	for n, ok := range A.OptimalCluster {
		if ok {
			Children[all.GetByName(n)] = true

		}
	}

	return Children
}

//Returns all the bridges of the current Graph
func GetBridges(all LocalityNodes, Root *LocalityNode) map[*LocalityNode]map[*LocalityNode]bool {

	DFS := dfs{
		0,
		make(map[*LocalityNode]bool),
		make(map[*LocalityNode]int),
		make(map[*LocalityNode]int),
		make(map[*LocalityNode]map[*LocalityNode]bool),
	}

	Bridges := recursive(all, Root, nil, &DFS)

	return Bridges
}

//Recursive Alogorithm Called to get The Bridges of the current Graph
func recursive(all LocalityNodes, A *LocalityNode, B *LocalityNode, Attributes *dfs) map[*LocalityNode]map[*LocalityNode]bool {

	Attributes.state[A] = true
	Attributes.timer++
	Attributes.tin[A], Attributes.fup[A] = Attributes.timer, Attributes.timer

	for _, c := range all.All {

		Attributes.Bridges[c] = make(map[*LocalityNode]bool)
	}

	for c, _ := range GetChildren(all, A) {

		if c == B {

			continue

		}

		if Attributes.state[c] {

			Attributes.fup[A] = int(math.Min(float64(Attributes.fup[A]), float64(Attributes.tin[c])))

		} else {
			recursive(all, c, A, Attributes)

			Attributes.fup[A] = int(math.Min(float64(Attributes.fup[A]), float64(Attributes.fup[c])))

			if Attributes.fup[c] > Attributes.tin[A] {

				Attributes.Bridges[A][c] = true
				Attributes.Bridges[c][A] = true
			}

		}
	}
	return Attributes.Bridges
}

func dfss(Dist map[*LocalityNode]map[*LocalityNode]float64, all LocalityNodes, radius float64, PathLength float64, nodeA *LocalityNode, nodeB *LocalityNode, IsVisited map[string]bool, Path []string, Paths *[][]string) {
	log.LLvl1(Path)

	//Marks the node as visited
	IsVisited[nodeA.Name] = true
	//If it reaches the destination it adds the local Path to all of the othe paths
	if nodeA.Name == nodeB.Name {
		//Copys the path
		Path2 := make([]string, len(Path))
		for i, _ := range Path {

			Path2[i] = Path[i]
		}
		*Paths = append(*Paths, Path2)

	}

	//Returns if the path is longer that the constraint
	if PathLength > radius {
		return
	}

	AdjacentNodes := make([]*LocalityNode, 0)

	for k, v := range nodeA.OptimalBunch {
		if v {
			AdjacentNodes = append(AdjacentNodes, all.GetByName(k))
		}
	}

	for k, v := range nodeA.OptimalCluster {
		if v {
			AdjacentNodes = append(AdjacentNodes, all.GetByName(k))
		}
	}

	for _, n := range AdjacentNodes {

		if !IsVisited[n.Name] {

			//Appends node to the current local path
			Path = append(Path, n.Name)

			//Updates the Pathlength
			PathLength = PathLength + Dist[nodeA][n]

			//Calls dfss as a recursion
			dfss(Dist, all, radius, PathLength, n, nodeB, IsVisited, Path, Paths)

			//Updates the Pathlength
			PathLength = PathLength - Dist[nodeA][n]

			//Removes node from current path
			Path = Path[:len(Path)-1]
		}

	}

	//Marks the node as not visited
	IsVisited[nodeA.Name] = false

}

/*
func MinDist(all LocalityNodes, Path *[]string, pathLen *int, nodeA *LocalityNode, nodeB *LocalityNode,
dist2 *map[*LocalityNode]map[*LocalityNode]float64,
Links *map[*LocalityNode]map[*LocalityNode]map[*LocalityNode]bool) bool {

	if nodeA == nodeB {
		return true
	}

	if nodeA.OptimalBunch[nodeB.Name] || nodeB.OptimalBunch[nodeA.Name] {
		//Sets distances for nodes in nodeA's Bunch
		return true
	}

	//Sets distances to itself to 0

	if *pathLen > 3 {
		return true
	}

	res := false

	for k, exists := range nodeA.OptimalBunch {
		//Looks for links in nodeA's OptimalBunch
		//

		//log.LLvl1("1 going through", k, "pathlen", *pathLen)

		nodeK := all.GetByName(k)
		if exists {
			(*pathLen)++
			*Path = append(*Path, k)
			res = MinDist(all, Path, pathLen, nodeK, nodeB, dist2, Links)
			*Path = (*Path)[0:len(*Path) - 1]
			(*pathLen)--
			newDist := (*dist2)[nodeA][nodeK] + (*dist2)[nodeK][nodeB]
			if res && newDist < (*dist2)[nodeA][nodeB] {
				(*dist2)[nodeA][nodeB] = newDist
				(*dist2)[nodeB][nodeA] = newDist
				(*Links)[nodeA][nodeB][nodeK] = true

			}
			if (*dist2)[nodeA][nodeB] <= 5 * ComputeDist(nodeA, nodeB) {
				return true
			}

		}
	}

	for k, exists := range nodeB.OptimalBunch {
		//log.LLvl1("2 going through", k, "pathlen", *pathLen)

		if exists {
			nodeK := all.GetByName(k)
			(*pathLen)++
			*Path = append(*Path, k)
			res = MinDist(all, Path, pathLen, nodeA, nodeK, dist2, Links)
			*Path = (*Path)[0:len(*Path) - 1]
			(*pathLen)--
			newDist := (*dist2)[nodeA][nodeK] + (*dist2)[nodeK][nodeB]
			if res && newDist < (*dist2)[nodeA][nodeB] {
				(*dist2)[nodeA][nodeB] = newDist
				(*dist2)[nodeB][nodeA] = newDist
				(*Links)[nodeA][nodeB][nodeK] = true
				(*pathLen)++
			}
			if (*dist2)[nodeA][nodeB] <= 5 * ComputeDist(nodeA, nodeB) {
				return true
			}

		}
	}

	if res {
		return true
	}
	return false
}
*/

func approxDistance(all LocalityNodes, nodeU *LocalityNode, nodeV *LocalityNode) float64 {

	w := nodeU
	i := 0

	for {
		found := false

		//log.LLvl1("w=", w.Name, "i=", i)

		if nodeV.Bunch[w.Name] {
			found = true
			break
		}

		i++
		if found {
			break
		}

		if i == 3 {
			log.Error("shouldn't get here!", nodeU.Name,
				nodeV.Name, nodeU.OptimalBunch, nodeV.OptimalBunch)
		}
		aux := nodeU
		nodeU = nodeV
		nodeV = aux

		for _, n := range all.All {
			if n.Name == nodeU.PDist[i] {
				w = n
				break
			}
		}
	}

	//Links[nodeU][nodeV][w] = true
	//Links[nodeV][nodeU][w] = true
	if all.ClusterBunchDistances[w][nodeU] == math.MaxFloat64 || all.ClusterBunchDistances[w][nodeV] == math.MaxFloat64 {
		log.Error("shouldn't get here!bad distances", nodeU.Name,
			nodeV.Name)
		log.Error(nodeU.OptimalBunch, nodeU.OptimalCluster, nodeU.PDist)
		log.Error(nodeV.OptimalBunch, nodeV.OptimalCluster, nodeV.PDist)
	}

	return all.ClusterBunchDistances[w][nodeU] + all.ClusterBunchDistances[w][nodeV]
}

func AproximateDistanceOracle(all LocalityNodes) (map[*LocalityNode]map[*LocalityNode]float64) {

	//Creates maps for links and distances
	dist2 := make(map[*LocalityNode]map[*LocalityNode]float64)



	/*
			if u.Name == v.Name {
				return u.Name, 0
			}
			w := u
			i := 0

			for {
				found := false
				for _, b1 := range v.bunch {
					if b1 == w.Name {
						found = true
						break
					}
				}
				i++
				if found {
					break
				}

				if i == K {
					log.Error("should get here!", u.Name, v.Name, u.bunch, v.bunch)
				}
				aux := u
				u = v
				v = aux
				for _,n := range nodes {
					if n.Name == u.pDist[i] {
						w = n
						break
					}
				}
			}

			return w.Name, euclidianDist(w,u) + euclidianDist(w,v)
			 */


	for _, aux := range all.All {

		dist2[aux] = make(map[*LocalityNode]float64)

		for _, aux2 := range all.All {
			dist2[aux][aux2] = all.ClusterBunchDistances[aux][aux2]
		}
	}

	for _, nodeU := range all.All {

		for _, nodeV := range all.All {

			if nodeU.Name == nodeV.Name {
				dist2[nodeU][nodeV] = 0
				continue
			}

			dist2[nodeU][nodeV] = approxDistance(all, nodeU, nodeV)
			//log.LLvl1("!!!!!!!!!!!!!!!!!!!! distance between", nodeU.Name, nodeV.Name, dist2[nodeU][nodeV])

		}
	}




	/*
	for i, nodeA := range all.All {

		for j, nodeB := range all.All {

			if j > i {
				break
			}

			if dist2[nodeA][nodeB] < math.MaxFloat64 {
				continue
			}

			pathLen := 0
			Path := make([]string, 0)

			MinDist(all, &Path, &pathLen, nodeA, nodeB, &dist2, &Links)
			log.LLvl1("computing dist between", nodeA.Name, nodeB.Name, dist2[nodeA][nodeB], Path)

			/*

			if nodeA.OptimalBunch[nodeB.Name] {
				//Sets distances for nodes in nodeA's Bunch
				dist2[nodeA][nodeB] = dist[nodeA][nodeB]

				dist2[nodeB][nodeA] = dist[nodeA][nodeB]
				continue
			}
			if nodeB.OptimalBunch[nodeA.Name] {
				//Sets distances for nodes in nodeA's Cluster

				dist2[nodeA][nodeB] = dist[nodeA][nodeB]
				dist2[nodeB][nodeA] = dist[nodeA][nodeB]
				continue
			}
			//Sets distances to itself to 0
			if nodeA == nodeB {
				dist2[nodeA][nodeB] = 0
				dist2[nodeB][nodeA] = 0
				continue
			}

			PossibleLinks := make(map[*LocalityNode]bool)


			for k, exists := range nodeA.OptimalBunch {
				//Looks for links in nodeA's OptimalBunch
				//
				if !exists {
					continue
				}




			//Checks for the existance of the link in nodeB's OptimalBunch and for the distance


			if nodeB.OptimalBunch[k] && (dist[nodeA][all.GetByName(k)] + dist[all.GetByName(k)][nodeB]) < minDist {

					PossibleLinks = make(map[*LocalityNode]bool)
					//Updates mindist
					minDist = dist[nodeA][all.GetByName(k)] + dist[all.GetByName(k)][nodeB]

					PossibleLinks[all.GetByName(k)] = true
					//Gets the links of previous links
					for k, _ := range Links[nodeA][all.GetByName(k)] {

						PossibleLinks[k] = true
					}
					//Gets the links of previous links

					for k, _ := range Links[all.GetByName(k)][nodeB] {

						PossibleLinks[k] = true
					}

				}

			}
			//Adds the links one it finds the smallest distance
			for k, _ := range PossibleLinks {

				Links[nodeA][nodeB][k] = true
				Links[nodeB][nodeA][k] = true

			}
			//Sets the distances
			dist2[nodeA][nodeB] = minDist
			dist2[nodeB][nodeA] = minDist


		}
	}
*/

	return dist2
}

/*
func GetRingNrBasedOnDist(all LocalityNodes, Node *LocalityNode, Dist float64) int {

	radiuses := GenerateRadius(CoumputeMaxDist(all, Node))

	for i, d := range radiuses {

		if Dist < d {
			return i + 1
		}

	}

	return -1
}

func CoumputeMaxDist(all LocalityNodes, node *LocalityNode) float64 {

	maxDist := 0.0

	for clusterNode := range node.Cluster {

		crtDist := ComputeDist(node, all.GetByName(clusterNode))
		if crtDist > maxDist {
			maxDist = crtDist
		}
	}

	return maxDist
}
*/

type dfs struct {
	timer   int
	state   map[*LocalityNode]bool
	tin     map[*LocalityNode]int
	fup     map[*LocalityNode]int
	Bridges map[*LocalityNode]map[*LocalityNode]bool
}