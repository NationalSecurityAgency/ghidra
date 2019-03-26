/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.util.graph;

import java.util.*;

import ghidra.util.Msg;
import ghidra.util.exception.NoValueException;
import ghidra.util.graph.attributes.*;

/** Base implementation of a directed graph. A directed graph consists
 * of a set of vertices (implemented as a VertexSet) and a set of edges
 * (implemented as an EdgeSet) joining ordered pairs of vertices in the
 * graph. Both vertices and edges can belong to more than one DirectedGraph.
 * Attributes for both vertices and edges may be defined for a DirectedGraph.
 * Parallel edges (more than one edge with the same from and to vertices)
 * are allowed in DirectedGraph. Loops are also allowed.
 * 
 * 
 */
public class DirectedGraph {
	private final VertexSet vertices;
	private final EdgeSet edges;
	private final AttributeManager<Vertex> vertexAttributes;
	private final AttributeManager<Edge> edgeAttributes;

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	//    Constructors                                                  //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////
	/** Creates an empty DirectedGraph with room for 
	 * vertexCapacity vertices and edgeCapacity edges.
	 */
	public DirectedGraph(int vertexCapacity, int edgeCapacity) {
		vertices = new VertexSet(this, vertexCapacity);
		edges = new EdgeSet(this, edgeCapacity);
		vertexAttributes = new AttributeManager<Vertex>(vertices);
		edgeAttributes = new AttributeManager<Edge>(edges);
	}

	/** Default constructor */
	public DirectedGraph() {
		this(101, 101);
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	//    Public Methods returning ints, doubles, etc.                  //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	/** The number of edges having v as their terminal or
	 *  "to" vertex.
	 */
	public int inValence(Vertex v) {
		int inv = 0;
		Edge e = vertices.getFirstIncomingEdge(v);
		while (e != null) {
			inv++;
			e = edges.getNextEdgeWithSameTo(e);
		}
		return inv;
	}

	/** The number of edges having v as their initial or
	 *  "from" vertex.
	 */
	public int outValence(Vertex v) {
		int outv = 0;
		Edge e = vertices.getFirstOutgoingEdge(v);
		while (e != null) {
			outv++;
			e = edges.getNextEdgeWithSameFrom(e);
		}
		return outv;
	}

	/** The number of edges having v as both their terminal and
	 *  terminal vertex.
	 */
	public int numLoops(Vertex v) {
		int loops = 0;
		Edge e = vertices.getFirstOutgoingEdge(v);
		while (e != null) {
			if (v.key() == e.to().key()) {
				loops++;
			}
			e = edges.getNextEdgeWithSameFrom(e);
		}
		return loops;
	}

	/** The number of edges incident with v. For unweighted
	 *   graphs valence and degree are the same, except valence is an int
	 *  while degree is a double.
	 */
	public int valence(Vertex v) {
		return (inValence(v) + outValence(v) - numLoops(v));
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	//    Package Methods returning Vertices, Edges and Collections     //
	//    containing Vertices and Edges.                                //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	/** Returns the EdgeSet of this graph. */
	public EdgeSet edges() {
		return edges;
	}

	/** 
	 * @param key
	 * @return the edge in the graph with the specified key or null
	 * if the graph does not contain an edge with the key.
	 */
	public Edge getEdgeWithKey(long key) {
		return edges.getKeyedObject(key);
	}

	/** Returns the VertexSet of this graph. */
	public VertexSet vertices() {
		return vertices;
	}

	/** 
	 * @param key
	 * @return the vertex in the graph with the specified key or null
	 * if the graph does not contain an vertex with the key.
	 */
	public Vertex getVertexWithKey(long key) {
		return vertices.getKeyedObject(key);
	}

	/** Returns a Set (HashSet) containing all vertices that are the tos
	 *   of outgoing edges of the given vertex. Note in the case of multiple
	 *  edges, the number of children and outvalence need not be the same.
	 */
	public Set<Vertex> getChildren(Vertex v) {
		Set<Vertex> children = new HashSet<Vertex>();
		Edge e = vertices.getFirstOutgoingEdge(v);
		while (e != null) {
			children.add(e.to());
			e = edges.getNextEdgeWithSameFrom(e);
		}
		return children;
	}

	/** Returns the outgoing edges from the given vertex. */
	public Set<Edge> getOutgoingEdges(Vertex v) {
		Set<Edge> outgoingEdges = new HashSet<Edge>();
		Edge e = vertices.getFirstOutgoingEdge(v);
		while (e != null) {
			outgoingEdges.add(e);
			e = edges.getNextEdgeWithSameFrom(e);
		}
		return outgoingEdges;
	}

	/** Returns a Set containg all of the vertices from which an edge comes
	 *  into the given vertex.
	 */
	public Set<Vertex> getParents(Vertex v) {
		Set<Vertex> parents = new HashSet<Vertex>();
		Edge e = vertices.getFirstIncomingEdge(v);
		while (e != null) {
			parents.add(e.from());
			e = edges.getNextEdgeWithSameTo(e);
		}
		return parents;
	}

	/** Returns a Set containing all of the edges to the given vertex. */
	public Set<Edge> getIncomingEdges(Vertex v) {
		Set<Edge> incomingEdges = new HashSet<Edge>();
		Edge e = vertices.getFirstIncomingEdge(v);
		while (e != null) {
			incomingEdges.add(e);
			e = edges.getNextEdgeWithSameTo(e);
		}
		return incomingEdges;
	}

	/** Returns all children of the vertices in the given set. */
	public Set<Vertex> getChildren(Set<Vertex> vs) {
		Set<Vertex> children = new HashSet<Vertex>();
		Vertex v;
		Edge e;
		Iterator<Vertex> i = vs.iterator();
		while (i.hasNext()) {
			v = i.next();
			e = vertices.getFirstOutgoingEdge(v);
			while (e != null) {
				children.add(e.to());
				e = edges.getNextEdgeWithSameFrom(e);
			}
		}
		return children;
	}

	/** Returns all parents of the vertices in the given set. */
	public Set<Vertex> getParents(Set<Vertex> vs) {
		Set<Vertex> parents = new HashSet<Vertex>();
		Edge e;
		Vertex v;
		Iterator<Vertex> i = vs.iterator();
		while (i.hasNext()) {
			v = i.next();
			e = vertices.getFirstIncomingEdge(v);
			while (e != null) {
				parents.add(e.from());
				e = edges.getNextEdgeWithSameTo(e);
			}
		}
		return parents;
	}

	/** Returns a Set (HashSet) containing all descendants of the given vertex.
	 *  Note: The vertex is defined to be a descendant of itself.
	 */
	public Set<Vertex> getDescendants(Vertex v) {
		Set<Vertex> seeds = new HashSet<Vertex>(11);
		seeds.add(v);
		Set<Vertex> descendants = new HashSet<Vertex>(vertices.size() / 20);
		Set<Vertex> newSeeds = new HashSet<Vertex>();
		Iterator<Vertex> i;
		Vertex vertex, child;
		Edge e;

		descendants.add(v); //Every vertex is by definition it own descendant
		while (!seeds.isEmpty()) {
			newSeeds.clear();
			i = seeds.iterator();
			while (i.hasNext()) {
				vertex = i.next();
				e = vertices.getFirstOutgoingEdge(vertex);
				while (e != null) {
					child = e.to();
					if (descendants.add(child)) {
						newSeeds.add(child);
					}
					e = edges.getNextEdgeWithSameFrom(e);
				}
			}
			seeds.clear();
			seeds.addAll(newSeeds);
		}
		return descendants;
	}

	/** Returns an array of all incoming edges. */
	public Edge[] incomingEdges(Vertex v) {
		int n = inValence(v);
		Edge[] answer = new Edge[n];
		Edge e = vertices.getFirstIncomingEdge(v);
		for (int i = 0; i < n; i++) {
			answer[i] = e;
			e = edges.getNextEdgeWithSameTo(e);
		}
		return answer;
	}

	/** Returns an array of all outgoing edges. */
	public Edge[] outgoingEdges(Vertex v) {
		int n = outValence(v);
		Edge[] answer = new Edge[n];
		Edge e = vertices.getFirstOutgoingEdge(v);
		for (int i = 0; i < n; i++) {
			answer[i] = e;
			e = edges.getNextEdgeWithSameFrom(e);
		}
		return answer;
	}

	/** Returns an array of all edges with the given vertex as both the from
	 *   and to.
	 */
	public Edge[] selfEdges(Vertex v) {
		int n = numLoops(v);
		Edge[] answer = new Edge[n];
		Edge e = vertices.getFirstOutgoingEdge(v);
		int i = 0;
		while (e != null) {
			if (v.equals(e.to())) {
				answer[i++] = e;
			}
			e = edges.getNextEdgeWithSameFrom(e);
		}
		return answer;
	}

	/** Returns array of all vertices unreachable from a source. These are the
	 *   vertices descending only from a non-trivial strongly connected component.
	 */
	public Vertex[] verticesUnreachableFromSources() {
		Set<Vertex> reachable = this.getDescendants(this.getSources());
		Set<Vertex> unreachable = vertices.toSet();
		unreachable.removeAll(reachable);
		return unreachable.toArray(new Vertex[unreachable.size()]);
	}

	/** Returns a Set (HashSet) of all vertices descended from a vertex in the
	 *  given array.
	 */
	public Set<Vertex> getDescendants(Vertex[] seedVertices) {
		Edge edge;
		Vertex parent, child;
		Set<Vertex> descendants = new HashSet<Vertex>(2 * seedVertices.length);
		Set<Vertex> pending = new HashSet<Vertex>(seedVertices.length);
		Set<Vertex> newlyPending = new HashSet<Vertex>(seedVertices.length);
		for (Vertex seedVertice : seedVertices) {
			pending.add(seedVertice);
		}

		while (!pending.isEmpty()) {
			Iterator<Vertex> iter = pending.iterator();
			while (iter.hasNext()) {
				parent = iter.next();
				edge = vertices.getFirstOutgoingEdge(parent);
				descendants.add(parent);
				iter.remove();
				while (edge != null) {
					child = edge.to();
					if (!descendants.contains(child)) {
						newlyPending.add(child);
					}
					edge = edges.getNextEdgeWithSameFrom(edge);
				}
			}
			pending.addAll(newlyPending);
			newlyPending.clear();
		}
		return descendants;
	}

	/** Returns a set of all the vertices which are ancestors of the given vertex.
	 *   Note: By definition a vertex is one of its own ancestors.
	 */
	public Set<Vertex> getAncestors(Vertex v) {
		Set<Vertex> seeds = new HashSet<Vertex>(11);
		seeds.add(v);
		Set<Vertex> ancestors = new HashSet<Vertex>(this.numVertices() / 20);
		Set<Vertex> newSeeds = new HashSet<Vertex>();
		Iterator<Vertex> i;
		Vertex vertex, parent;
		Edge e;

		ancestors.add(v);
		while (!seeds.isEmpty()) {
			newSeeds.clear();
			i = seeds.iterator();
			while (i.hasNext()) {
				vertex = i.next();
				e = vertices.getFirstIncomingEdge(vertex);
				while (e != null) {
					parent = e.from();
					if (ancestors.add(parent)) {
						newSeeds.add(parent);
					}
					e = edges.getNextEdgeWithSameTo(e);
				}
			}
			seeds.clear();
			seeds.addAll(newSeeds);
		}
		ancestors.add(v);
		return ancestors;
	}

	/** Returns an iterator for the EdgeSet of this graph. */
	public GraphIterator<Edge> edgeIterator() {
		return edges.iterator();
	}

	/** Returns an iterator for the VertexSet of this graph.  */
	public GraphIterator<Vertex> vertexIterator() {
		return vertices.iterator();
	}

	//  /** Debugging use only. */
	//  public void verbosePrint()
	//  {
	//      vertices.verbosePrint();
	//      edges.verbosePrint();
	//  }

	/** Returns inValence as a double. Should be overridden extending classes. */
	public double inDegree(Vertex v) {
		return inValence(v);
	}

	/** Returns outValence as a double. Should be overridden extending classes. */
	public double outDegree(Vertex v) {
		return outValence(v);
	}

	/** Returns numLoops as a double. Should be overridden extending classes. */
	public double loopDegree(Vertex v) {
		return numLoops(v);
	}

	/** Returns valence as a double. Should be overridden extending classes. */
	public double degree(Vertex v) {
		return valence(v);
	}

	/** Returns true iff all nodes and edges of the given graph are in the current graph
	 */
	public boolean containsAsSubgraph(DirectedGraph g) {
		boolean test = true;
		GraphIterator<Edge> ei = g.edgeIterator();
		while (ei.hasNext() && test) {
			test = this.contains(ei.next());
		}
		GraphIterator<Vertex> vi = g.vertices.iterator();
		while (vi.hasNext() && test) {
			test = this.contains(vi.next());
		}
		return test;
	}

	/** Returns an array of Sets (HashSet). Each set contains the vertices
	 *  within a single strongly connected component of the DirectedGraph.
	 * 
	 * A strongly connected component of a directed graph is a subgraph 
	 * in which it is possible to find a directed path from any vertex to any 
	 * other vertex in the graph. A cycle is a simple example of strongly 
	 * connected graph.
	 */
	@SuppressWarnings("unchecked")
	// we know our array is of the correct type
	public Set<Vertex>[] assignVerticesToStrongComponents() {
		DepthFirstSearch dfsa = new DepthFirstSearch(this, this.getSources(), true, true, false);
		DepthFirstSearch dfsb =
			new DepthFirstSearch(this, dfsa.topologicalSort(), true, false, true);
		//Err.debug(this, "The number of SCCs is " + dfsb.seedsUsed.size());
		Set<Vertex> sccSeeds = new HashSet<Vertex>(dfsb.seedsUsed());
		Set<Vertex>[] sccVertices = new Set[sccSeeds.size()]; // triggers unchecked warning
		Vertex[] finishOrder = dfsb.topologicalSort();
		int n = finishOrder.length;
		int j = 0;
		for (int i = 0; i < sccSeeds.size(); i++) {
			sccVertices[i] = new HashSet<Vertex>(1);
			do {
				//Err.debug(this,  Long.toHexString(finishOrder[j].getName() ) + " ");
				sccVertices[i].add(finishOrder[j++]);
			}
			while ((j < n) && !sccSeeds.contains(finishOrder[j]));
			//Err.debug(this, " | ");
		}
		return sccVertices;
	}

	/** Returns a vector containing the entry points to a directed graph. An entry
	 *  point is either a source (in valence zero) or the least vertex in a strongly
	 *  connected component unreachable from any vertex outside the strongly
	 *  connected component. Least is defined here to be the vertex with the smallest
	 *  key.
	 */
	public Vector<Vertex> getEntryPoints() {

		Vertex[] sources = this.vertices().getSources();
		Set<Vertex> entryPointSet = new TreeSet<Vertex>();
		Vector<Vertex> entryPoints = new Vector<Vertex>(sources.length);
		for (Vertex source : sources) {
			entryPointSet.add(source);
		}
		Set<Vertex> descendantsOfSources = this.getDescendants(sources);
		Set<Vertex> nonDescendants = this.vertices().toSet();
		nonDescendants.removeAll(descendantsOfSources);
		if (nonDescendants.size() > 0) {
			Vertex u, v = null;
			Vertex[] nonDescendantVertices = nonDescendants.toArray(new Vertex[0]);
			DirectedGraph g = this.inducedSubgraph(nonDescendantVertices);
			Iterator<Vertex> iter;
			Set<Vertex>[] strongComponents = g.assignVerticesToStrongComponents();
			int n = strongComponents.length;
			for (int i = 0; i < n; i++) {
				iter = strongComponents[i].iterator();
				if (iter.hasNext()) {
					u = iter.next();
					Set<Vertex> parents = this.getParents(u);
					while (iter.hasNext()) {
						v = iter.next();
						parents.addAll(this.getParents(v));
						if (v.key() < u.key()) {
							u = v;
						}
					}
					if (strongComponents[i].containsAll(parents)) {
						entryPointSet.add(u);
					}
				}
			}
		}
		Iterator<Vertex> iter = entryPointSet.iterator();
		while (iter.hasNext()) {
			entryPoints.add(0, iter.next());
		}
		return entryPoints;
	}

	/** returns a java.util.Set containing the vertices in this graph.
	 */
	public Set<Vertex> getVertices() {
		return this.vertices().toSet();
	}

	/** returns an array containing the vertices in the graph
	 */
	public Vertex[] getVertexArray() {
		return vertices.toArray();
	}

	/** returns a java.util.Set containing the edges in this graph. */
	public Set<Edge> getEdges() {
		return this.edges().toSet();
	}

	/** returns an array containing the edges in the graph
	 */
	public Edge[] getEdgeArray() {
		return edges.toArray();
	}

	/** Returns the number of vertices in the graph */
	public int numVertices() {
		return this.vertices().size();
	}

	/** Returns the number of edges in the graph */
	public int numEdges() {
		return this.edges().size();
	}

	/** Adds the specified vertex to the graph. */
	public boolean add(Vertex v) {
		return this.vertices().add(v);
	}

	/** Adds the specified edge to the graph. If either endpoint of the
	 * edge is not in the graph that vertex is also added to the graph.
	 */
	public boolean add(Edge e) {
		return this.edges().add(e);
	}

	/** Removes the vertex v from the graph. Also removes all edges incident with
	 * v. Does nothing if the vertex is not in the graph.
	 */
	public boolean remove(Vertex v) {
		return this.vertices().remove(v);
	}

	/** Removes Edge e from the graph. No effect if the edge is not in the graph.
	 */
	public boolean remove(Edge e) {
		return this.edges().remove(e);
	}

	/** Returns true iff the vertex is in the graph. 
	 */
	public boolean contains(Vertex v) {
		return this.vertices().contains(v);
	}

	/** Returns true iff the graph contains the edge e. */
	public boolean contains(Edge e) {
		return this.edges().contains(e);
	}

	/** returns the number of vertices with outValence zero. */
	public int numSinks() {
		return this.vertices().numSinks();
	}

	/** returns the number of vertices with inValence zero. */
	public int numSources() {
		return this.vertices().numSources();
	}

	/** Returns a Vertex[] containing the sources. A vertex is a source if
	 * it has no incoming edges.
	 */
	public Vertex[] getSources() {
		return this.vertices().getSources();
	}

	/** Returns a Vertex[] containing the sinks. A vertex is a sink if it 
	 * has no outgoing edges.
	 */
	public Vertex[] getSinks() {
		return this.vertices().getSinks();
	}

	/** Returns a java.util.Set containing all of the vertices within the
	 *  same component a the given vertex.
	 */
	public Set<Vertex> getVerticesInContainingComponent(Vertex v) {
		Set<Vertex> verticesInComponent = new HashSet<Vertex>();
		Set<Vertex> toDo = new HashSet<Vertex>();
		Set<Vertex> toDoNext = new HashSet<Vertex>();
		Set<Vertex> neighborhood;
		Iterator<Vertex> i;
		Vertex u;

		toDo.add(v);
		while (!toDo.isEmpty()) {
			neighborhood = this.getNeighborhood(toDo);
			i = neighborhood.iterator();
			while (i.hasNext()) {
				u = i.next();
				if ((!verticesInComponent.contains(u)) && (!toDo.contains(u))) {
					toDoNext.add(u);
					verticesInComponent.add(u);
				}
			}
			toDo.clear();
			toDo.addAll(toDoNext);
			toDoNext.clear();
		}
		return verticesInComponent;
	}

	/** Returns the subgraph of this graph which is the component containing v. */
	public DirectedGraph getComponentContaining(Vertex v) {
		Vertex[] verts = this.getVerticesInContainingComponent(v).toArray(new Vertex[0]);
		return this.inducedSubgraph(verts);
	}

	/** Returns an array of directed graphs. Each array element is a 
	 * DirectedGraph consisting of a single
	 * connected component of this graph.
	 */
	public DirectedGraph[] getComponents() {
		Vertex u, v;
		Edge e;
		DirectedGraph g;
		Set<Vertex> accountedFor = new HashSet<Vertex>(this.numVertices());
		Set<Vertex> toDo = new HashSet<Vertex>(this.numVertices());
		List<DirectedGraph> components = new ArrayList<DirectedGraph>();
		GraphIterator<Vertex> vertIter = this.vertexIterator();
		Iterator<Vertex> iter;
		int i;

		while (vertIter.hasNext()) {
			v = vertIter.next();
			if (!accountedFor.contains(v)) {
				//start a new graph grown out from v
				g = new DirectedGraph();
				toDo.add(v);
				while (!toDo.isEmpty()) {
					//get a vertex in toDo
					iter = toDo.iterator();
					if (iter.hasNext()) {
						u = iter.next();
						g.add(u);
						accountedFor.add(u);
						Edge[] incomingEdges = this.incomingEdges(u);
						for (i = 0; i < incomingEdges.length; i++) {
							e = incomingEdges[i];
							g.add(e);
							if (!accountedFor.contains(e.from())) {
								toDo.add(e.from());
							}
						}
						Edge[] outgoingEdges = this.outgoingEdges(u);
						for (i = 0; i < outgoingEdges.length; i++) {
							e = outgoingEdges[i];
							g.add(e);
							if (!accountedFor.contains(e.to())) {
								toDo.add(e.to());
							}
						}
						Edge[] selfEdges = this.selfEdges(u);
						for (i = 0; i < selfEdges.length; i++) {
							e = selfEdges[i];
							g.add(e);
						}
						toDo.remove(u);
					}
				}
				components.add(g);
			}
		}
		return components.toArray(new DirectedGraph[0]);
	}

	/** Creates intersection of graphs in place by adding all vertices and edges of
	 * other graph to this graph. This method used to return a different graph
	 * as the intersection but now does not.
	 */
	public void intersectionWith(DirectedGraph otherGraph) {
		GraphIterator<Vertex> vi = otherGraph.vertices.iterator();
		Vertex v;
		while (vi.hasNext()) {
			v = vi.next();
			if (!this.contains(v)) {
				vi.remove();
			}
		}
		GraphIterator<Edge> ei = otherGraph.edgeIterator();
		Edge e;
		while (ei.hasNext()) {
			e = ei.next();
			if (!this.contains(e)) {
				ei.remove();
			}
		}
	}

	/** Creates union of graphs in place by adding all vertices and edges of
	 * other graph to this graph. This method used to return a different graph
	 * as the union but now does not.
	 */
	public void unionWith(DirectedGraph otherGraph) {
		GraphIterator<Vertex> vi = otherGraph.vertexIterator();
		while (vi.hasNext()) {
			add(vi.next());
		}
		GraphIterator<Edge> ei = otherGraph.edgeIterator();
		while (ei.hasNext()) {
			add(ei.next());
		}
	}

	/** Get the graph induced by the seed vertices and their descendants */
	public DirectedGraph descendantsGraph(Vertex[] seeds) {
		Vertex[] descendants = this.getDescendants(seeds).toArray(new Vertex[0]);
		return this.inducedSubgraph(descendants);
	}

	/** Returns the directed graph which is subgraph induced by the given
	 *  set of vertices. The vertex set of the returned graph contains the
	 *  given vertices which belong to this graph. An edge of this graph
	 *  is in the returned graph iff both endpoints belong to the given vertices.
	 */
	public DirectedGraph inducedSubgraph(Vertex[] vertexSet) {
		DirectedGraph newGraph = new DirectedGraph(vertexSet.length, this.numEdges());
		for (Vertex element : vertexSet) {
			if (this.contains(element)) {
				newGraph.add(element);
			}
		}
		GraphIterator<Edge> ei = this.edgeIterator();
		Edge e;
		while (ei.hasNext()) {
			e = ei.next();
			if (newGraph.contains(e.from()) && newGraph.contains(e.to())) {
				newGraph.add(e);
			}
		}
		return newGraph;
	}

	/** Returns a java.util.Set containing the vertex v and its neighbors. */
	public Set<Vertex> getNeighborhood(Vertex v) {
		Set<Vertex> neighborhood = this.getChildren(v);
		neighborhood.addAll(this.getParents(v));
		neighborhood.add(v);
		return neighborhood;
	}

	/** Returns a java.util.Set containing the vertices in the given Set and their
	 *  neighbors.
	 */
	public Set<Vertex> getNeighborhood(Set<Vertex> vs) {
		Set<Vertex> neighborhood = new HashSet<Vertex>(2 * vs.size());
		Iterator<Vertex> iter = vs.iterator();
		while (iter.hasNext()) {
			neighborhood.addAll(getNeighborhood(iter.next()));
		}
		return neighborhood;
	}

	/** Returns the referent of the object used to create v if it exists. If the
	 *  vertex was created with a null referent this method returns null.
	 */
	public Object getReferent(Vertex v) {
		return v.referent();
	}

	/** This method assigns levels in a top-down manner. Sources are on level 0.
	 */
	public IntegerAttribute<Vertex> getLevels() {
		IntegerAttribute<Vertex> levels = new IntegerAttribute<Vertex>("Levels", this.vertices());
		DepthFirstSearch dfs = new DepthFirstSearch(this, this.getSources(), true, true, false);
		Vertex[] topologicalSort = dfs.topologicalSort();
		int numVertices = this.numVertices();
		int i, maxParentLevel;
		Vertex v, parent;
		Set<Vertex> parents;
		try {
			for (i = 0; i < numVertices; i++) {
				levels.setValue(topologicalSort[i], -1);
			}
			for (i = 0; i < numVertices; i++) {
				v = topologicalSort[i];
				parents = this.getParents(v);
				maxParentLevel = -1;
				Iterator<Vertex> iter = parents.iterator();
				while (iter.hasNext()) {
					parent = iter.next();
					if (levels.getValue(parent) > maxParentLevel) {
						maxParentLevel = levels.getValue(parent);
					}
				}
				levels.setValue(v, maxParentLevel + 1);
			}
		}
		catch (ghidra.util.exception.NoValueException exc) {
			Msg.error(this, "Bad set/get in getLevels()");
		}
		return levels;
	}

	/** Assigns levels to the graph in a bottom up fashion. All sinks have the
	 *  same level.
	 */
	public IntegerAttribute<Vertex> complexityDepth() {
		IntegerAttribute<Vertex> complexityDepth;
		if (vertexAttributes.hasAttributeNamed("ComplexityDepth")) {
			complexityDepth =
				(IntegerAttribute<Vertex>) vertexAttributes.getAttribute("ComplexityDepth");
			complexityDepth.clear();
		}
		else {
			complexityDepth =
				(IntegerAttribute<Vertex>) vertexAttributes.createAttribute("ComplexityDepth",
					AttributeManager.INTEGER_TYPE);
		}
		DepthFirstSearch dfs = new DepthFirstSearch(this, this.getSources(), true, true, false);
		Vertex[] topologicalSort = dfs.topologicalSort();
		int numVertices = this.numVertices();
		int i, maxChildLevel, maximumLevel = -1;
		Vertex v, child;
		Set<Vertex> children;
		try {
			for (i = 0; i < numVertices; i++) {
				complexityDepth.setValue(topologicalSort[i], -1);
			}
			for (i = numVertices - 1; i >= 0; i--) {
				v = topologicalSort[i];
				children = this.getChildren(v);
				maxChildLevel = -1;
				Iterator<Vertex> iter = children.iterator();
				while (iter.hasNext()) {
					child = iter.next();
					if (complexityDepth.getValue(child) > maxChildLevel) {
						maxChildLevel = complexityDepth.getValue(child);
					}
				}
				complexityDepth.setValue(v, maxChildLevel + 1);
				if (maxChildLevel + 1 > maximumLevel) {
					maximumLevel = maxChildLevel + 1;
				}
			}
		}
		catch (ghidra.util.exception.NoValueException exc) {
			Msg.error(this, "Bad get/set in complexityDepth()");
		}
		return complexityDepth;
	}

	/** Returns all edges joing the from and to vertices. Recall DirectedGraph
	 * uses a multigraph model where parallel edges are allowed.
	 */
	public Edge[] getEdges(Vertex from, Vertex to) {
		Edge e;
		Set<Edge> outgoingEdges = this.getOutgoingEdges(from);
		Iterator<Edge> iter = outgoingEdges.iterator();
		while (iter.hasNext()) {
			e = iter.next();
			if (e.to() != to) {
				iter.remove();
			}
		}
		return outgoingEdges.toArray(new Edge[0]);
	}

	/** Returns true iff the graph contains and edge from the parent vertex
	 * to the child vertex.
	 */
	public boolean areRelatedAs(Vertex parent, Vertex child) {
		Edge e;
		Set<Edge> outgoingEdges = this.getOutgoingEdges(parent);
		Iterator<Edge> iter = outgoingEdges.iterator();
		while (iter.hasNext()) {
			e = iter.next();
			if (e.to() == child) {
				return true;
			}
		}
		return false;
	}

	/** Removes all vertices and edges from the graph without changing 
	* the space allocated.
	*/
	public void clear() {
		this.edges.clear();
		this.vertices.clear();
		this.edgeAttributes.clear();
		this.vertexAttributes.clear();
	}

	/** Returns the AttributeManager for the vertices of this graph. */
	public AttributeManager<Vertex> vertexAttributes() {
		return this.vertexAttributes;
	}

	/** Returns the AttributeManager for the edges of this graph. */
	public AttributeManager<Edge> edgeAttributes() {
		return this.edgeAttributes;
	}

	/** Returns Vertex[] containing all vertices having the given object as
	*  a referent. Any number of vertices in the graph may refer back to 
	* the same object.
	*/
	public Vertex[] getVerticesHavingReferent(Object o) {
		int cnt = 0;
		if (o == null)
			return new Vertex[0];
		Vertex[] temp = new Vertex[this.numVertices()];
		GraphIterator<Vertex> iter = this.vertexIterator();
		while (iter.hasNext()) {
			Vertex v = iter.next();
			if (v.referent() != null && v.referent().equals(o))
				temp[cnt++] = v;
		}
		Vertex[] ans = new Vertex[cnt];
		System.arraycopy(temp, 0, ans, 0, cnt);
		return ans;
	}

	/**
	 * @return A directed graph with the same vertices, edges, and attributes.
	 */
	public DirectedGraph copy() {
		DirectedGraph copy = new DirectedGraph(this.numVertices(), this.numEdges());
		copyAll(copy);
		return copy;
	}

	/**
	 * Copies all attributes from the indicated directed graph to this one.
	 * @param copy the directed graph to copy from.
	 */
	protected void copyAll(DirectedGraph copy) {
		GraphIterator<Vertex> iter1 = this.vertexIterator();
		while (iter1.hasNext()) {
			Vertex v = iter1.next();
			//copyVertex( v, copy );
			copy.add(v);
		}
		CopyVertexAttributes(copy);
		GraphIterator<Edge> iter2 = this.edgeIterator();
		while (iter2.hasNext()) {
			Edge e = iter2.next();
			//copyEdge( e, copy );
			copy.add(e);
		}
		CopyEdgeAttributes(copy);
	}

	private void CopyEdgeAttributes(DirectedGraph copy) {
		AttributeManager<Edge> attm = this.edgeAttributes;
		AttributeManager<Edge> copyManager = copy.edgeAttributes();
		String[] names = attm.getAttributeNames();
		List<Attribute<Edge>> attrs = new ArrayList<Attribute<Edge>>(names.length);
		for (String name : names) {
			attrs.add(attm.getAttribute(name));
		}

		for (int i = 0; i < names.length; i++) {
			Attribute<Edge> attribute = attrs.get(i);
			if (attribute instanceof DoubleAttribute) {
				DoubleAttribute<Edge> dattr = (DoubleAttribute<Edge>) attribute;
				DoubleAttribute<Edge> dattrCopy =
					(DoubleAttribute<Edge>) copyManager.createAttribute(names[i],
						AttributeManager.DOUBLE_TYPE);
				GraphIterator<Edge> iter = this.edgeIterator();
				while (iter.hasNext()) {
					Edge v = iter.next();
					try {
						dattrCopy.setValue(v, dattr.getValue(v));
					}
					catch (NoValueException exc) {
						//do nothing
					}
				}
			}
			else if (attribute instanceof IntegerAttribute) {
				IntegerAttribute<Edge> dattr = (IntegerAttribute<Edge>) attribute;
				IntegerAttribute<Edge> dattrCopy =
					(IntegerAttribute<Edge>) copyManager.createAttribute(names[i],
						AttributeManager.INTEGER_TYPE);
				GraphIterator<Edge> iter = this.edgeIterator();
				while (iter.hasNext()) {
					Edge v = iter.next();
					try {
						dattrCopy.setValue(v, dattr.getValue(v));
					}
					catch (NoValueException exc) {
						//do nothing
					}
				}
			}
			else if (attribute instanceof LongAttribute) {
				LongAttribute<Edge> dattr = (LongAttribute<Edge>) attribute;
				LongAttribute<Edge> dattrCopy =
					(LongAttribute<Edge>) copyManager.createAttribute(names[i],
						AttributeManager.LONG_TYPE);
				GraphIterator<Edge> iter = this.edgeIterator();
				while (iter.hasNext()) {
					Edge v = iter.next();
					try {
						dattrCopy.setValue(v, dattr.getValue(v));
					}
					catch (NoValueException exc) {
						//do nothing
					}
				}
			}
			else if (attribute instanceof ObjectAttribute) {
				ObjectAttribute<Edge> dattr = (ObjectAttribute<Edge>) attribute;
				ObjectAttribute<Edge> dattrCopy =
					(ObjectAttribute<Edge>) copyManager.createAttribute(names[i],
						AttributeManager.OBJECT_TYPE);
				GraphIterator<Edge> iter = this.edgeIterator();
				while (iter.hasNext()) {
					Edge v = iter.next();
					dattrCopy.setValue(v, dattr.getValue(v));
				}
			}
			else if (attribute instanceof StringAttribute) {
				StringAttribute<Edge> dattr = (StringAttribute<Edge>) attribute;
				StringAttribute<Edge> dattrCopy =
					(StringAttribute<Edge>) copyManager.createAttribute(names[i],
						AttributeManager.STRING_TYPE);
				GraphIterator<Edge> iter = this.edgeIterator();
				while (iter.hasNext()) {
					Edge v = iter.next();
					dattrCopy.setValue(v, dattr.getValue(v));
				}
			}
		}
	}

	/**
	 * 
	 */
	private void CopyVertexAttributes(DirectedGraph copy) {
		AttributeManager<Vertex> attm = this.vertexAttributes;
		AttributeManager<Vertex> copyManager = copy.vertexAttributes();
		String[] names = attm.getAttributeNames();
		List<Attribute<Vertex>> attrs = new ArrayList<Attribute<Vertex>>();

		for (String name : names) {
			attrs.add(attm.getAttribute(name));
		}
		for (int i = 0; i < names.length; i++) {
			Attribute<Vertex> attribute = attrs.get(i);

			if (attribute instanceof DoubleAttribute) {
				DoubleAttribute<Vertex> dattr = (DoubleAttribute<Vertex>) attribute;
				DoubleAttribute<Vertex> dattrCopy =
					(DoubleAttribute<Vertex>) copyManager.createAttribute(names[i],
						AttributeManager.DOUBLE_TYPE);
				GraphIterator<Vertex> iter = this.vertexIterator();
				while (iter.hasNext()) {
					Vertex v = iter.next();
					try {
						dattrCopy.setValue(v, dattr.getValue(v));
					}
					catch (NoValueException exc) {
						//do nothing
					}
				}
			}
			else if (attribute instanceof IntegerAttribute) {
				IntegerAttribute<Vertex> dattr = (IntegerAttribute<Vertex>) attribute;
				IntegerAttribute<Vertex> dattrCopy =
					(IntegerAttribute<Vertex>) copyManager.createAttribute(names[i],
						AttributeManager.INTEGER_TYPE);
				GraphIterator<Vertex> iter = this.vertexIterator();
				while (iter.hasNext()) {
					Vertex v = iter.next();
					try {
						dattrCopy.setValue(v, dattr.getValue(v));
					}
					catch (NoValueException exc) {
						//do nothing
					}
				}
			}
			else if (attribute instanceof LongAttribute) {
				LongAttribute<Vertex> dattr = (LongAttribute<Vertex>) attribute;
				LongAttribute<Vertex> dattrCopy =
					(LongAttribute<Vertex>) copyManager.createAttribute(names[i],
						AttributeManager.LONG_TYPE);
				GraphIterator<Vertex> iter = this.vertexIterator();
				while (iter.hasNext()) {
					Vertex v = iter.next();
					try {
						dattrCopy.setValue(v, dattr.getValue(v));
					}
					catch (NoValueException exc) {
						//do nothing
					}
				}
			}
			else if (attribute instanceof ObjectAttribute) {
				ObjectAttribute<Vertex> dattr = (ObjectAttribute<Vertex>) attribute;
				ObjectAttribute<Vertex> dattrCopy =
					(ObjectAttribute<Vertex>) copyManager.createAttribute(names[i],
						AttributeManager.OBJECT_TYPE);
				GraphIterator<Vertex> iter = this.vertexIterator();
				while (iter.hasNext()) {
					Vertex v = iter.next();
					dattrCopy.setValue(v, dattr.getValue(v));
				}
			}
			else if (attribute instanceof StringAttribute) {
				StringAttribute<Vertex> dattr = (StringAttribute<Vertex>) attribute;
				StringAttribute<Vertex> dattrCopy =
					(StringAttribute<Vertex>) copyManager.createAttribute(names[i],
						AttributeManager.STRING_TYPE);
				GraphIterator<Vertex> iter = this.vertexIterator();
				while (iter.hasNext()) {
					Vertex v = iter.next();
					dattrCopy.setValue(v, dattr.getValue(v));
				}
			}
		}

	}

	/**
	 * This method copies a vertex and all object attributes from graph 
	 * 'other' into this graph. 
	 * @param node
	 * @param other
	 */
	protected void copyVertex(Vertex node, DirectedGraph other) {
		add(node);
		if (other != null)
			copyVertexAttributeValues(node, other);
	}

	/**
	 * This method copies an edge and all object attributes from graph 
	 * 'other' into this graph.  Any implicictly created Verticies do not 
	 * get their attribute values copied -- you must use copyVertex. 
	 * 
	 * @param e
	 * @param other
	 */
	protected void copyEdge(Edge e, DirectedGraph other) {

		Vertex srcVtx = e.from();
		Vertex dstVtx = e.to();
		Edge newe = new Edge(srcVtx, dstVtx);
		add(newe);
		copyEdgeAttributeValues(newe, e, other);

	}

	/**
	 * This method copies the attributes from an edge 'e' from DirectedGraph
	 * 'other' into this graph associated with edge 'newe'
	 * 
	 * @param newe
	 * @param e
	 * @param other
	 */
	protected void copyEdgeAttributeValues(Edge newe, Edge e, DirectedGraph other) {

		AttributeManager<Edge> aman = other.edgeAttributes();
		String vamNames[] = aman.getAttributeNames();
		for (int i = 0; i < vamNames.length; i++) {
			ObjectAttribute<Edge> att = (ObjectAttribute<Edge>) aman.getAttribute(vamNames[i]);
			if (!this.edgeAttributes().hasAttributeNamed(vamNames[i])) {
				this.edgeAttributes().createAttribute(vamNames[i], att.attributeType());
			}
			Object o = other.getEdgeProperty(vamNames[i], e);
			if (o != null)
				this.setEdgeProperty(vamNames[i], newe, o);
		}

	}

	/**
	 * This method joins nodes from a directed graph into this.  This 
	 * allows DirectedGraph subclasses to copy nodes and attributes, 
	 * a shortcomings with the unionWith method. 
	 *   
	 * @param other the other directed graph that is to be joined into this one.
	 * @return this directed graph
	 */
	public DirectedGraph join(DirectedGraph other) {
		GraphIterator<Vertex> nodes = other.vertices().iterator();
		while (nodes.hasNext()) {
			Vertex vert = nodes.next();
			copyVertex(vert, other);
		}

		GraphIterator<Edge> ei = other.edgeIterator();
		while (ei.hasNext()) {
			Edge e = ei.next();
			copyEdge(e, other);
		}
		return this;
	}

	/**
	 * This method copies vertex attributes for vertex 'vert' from graph
	 * 'other' to this graph.  
	 * @param vert the vertex whose attributes should be copied.
	 * @param other the other graph to copy vertex attributes from
	 */
	protected void copyVertexAttributeValues(Vertex vert, DirectedGraph other) {

		AttributeManager<Vertex> aman = other.vertexAttributes();
		String vamNames[] = aman.getAttributeNames();
		for (int i = 0; i < vamNames.length; i++) {
			ObjectAttribute<Vertex> att = (ObjectAttribute<Vertex>) aman.getAttribute(vamNames[i]);
			if (!this.vertexAttributes().hasAttributeNamed(vamNames[i])) {
				this.vertexAttributes().createAttribute(vamNames[i], att.attributeType());
			}
			Object o = other.getVertexProperty(vamNames[i], vert);
			if (o != null)
				this.setVertexProperty(vamNames[i], vert, o);
		}
	}

	/**
	 * This is a helper method that sets a object property named propName 
	 * to edge e.  
	 */
	protected void setEdgeProperty(String propName, Edge e, Object prop) {
		ObjectAttribute<Edge> attrib = getEdgeAttribute(propName);
		attrib.setValue(e, prop);
	}

	/**
	 * This is a helper method that gets a property named propName to
	 * from edge e.
	 * 
	 * @param propName the property name
	 * @param e the edge 
	 * @return the attribute for the indicated edge
	 */
	protected Object getEdgeProperty(String propName, Edge e) {
		ObjectAttribute<Edge> attrib = getEdgeAttribute(propName);
		Object o = attrib.getValue(e);

		return o;
	}

	/**
	 * This is a helper method that sets an object property named propName
	 * for Vertex v.  
	 * @param propName the property name
	 * @param v the vertex
	 * @param prop the property value
	 */
	protected void setVertexProperty(String propName, Vertex v, Object prop) {
		ObjectAttribute<Vertex> attrib = getVertexAttribute(propName);
		attrib.setValue(v, prop);
	}

	/**
	 * This is a helper method that gets a property named propName
	 * for vertex v.
	 * 
	 * @param propName the property name
	 * @param v the vertex
	 * @return the property value
	 */
	protected Object getVertexProperty(String propName, Vertex v) {
		ObjectAttribute<Vertex> attrib = getVertexAttribute(propName);
		return attrib.getValue(v);
	}

	/**
	 * This method gets and ObjectAttribute method give an attribute name.
	 * If it is not found in the attribute manager, the attribute is 
	 * created automatically.
	 * 
	 * @param attribName the name of the attribute
	 * @return the attribute
	 */
	protected ObjectAttribute<Edge> getEdgeAttribute(String attribName) {
		AttributeManager<Edge> am = edgeAttributes();
		Attribute<Edge> attrib = am.getAttribute(attribName);

		if (attrib == null) {
			attrib = edgeAttributes().createAttribute(attribName, AttributeManager.OBJECT_TYPE);
			Msg.debug(this, "creating edge property: " + attribName);

		}
		return (ObjectAttribute<Edge>) attrib;

	}

	/**
	 * This method gets and ObjectAttribute method give an attribute name.
	 * If it is not found in the attribute manager, the attribute is 
	 * created automatically.
	 * 
	 * @param attribName the attribute name
	 * @return the attribute
	 */
	protected ObjectAttribute<Vertex> getVertexAttribute(String attribName) {
		AttributeManager<Vertex> am = vertexAttributes();
		Attribute<Vertex> attrib = am.getAttribute(attribName);

		if (attrib == null) {
			attrib = vertexAttributes().createAttribute(attribName, AttributeManager.OBJECT_TYPE);
		}
		return (ObjectAttribute<Vertex>) attrib;
	}

	/** 
	 * This method converts a collection of verticies into a set of its
	 * referent objects.  It is up to the methods using the created set 
	 * to properly type cast the set's elements.
	 * 
	 * @param verts the vertices
	 * @return the set of referent objects
	 */
	public static Set<?> verts2referentSet(Collection<Vertex> verts) {
		Set<Object> s = new HashSet<Object>();
		Iterator<Vertex> vIter = verts.iterator();
		while (vIter.hasNext()) {
			Vertex vert = vIter.next();
			s.add(vert.referent());
		}
		return s;
	}

}
