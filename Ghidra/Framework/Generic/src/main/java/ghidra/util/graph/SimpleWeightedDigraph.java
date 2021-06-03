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

/**
 *
 * A simple graph is a graph with no parallel edges or loops. This class models
 * a simple digraph -- edges are directed and a single edge may go from any vertex
 * to any other vertex. {@literal It is possible to have edges A-->B and B-->A however.}
 * Attempting to add an edge from A to B when an edge from A to B already exists
 * causes the edge weight to be increased by the defaultEdgeWeight or the weight
 * specified. 
 * 
 * This class may be used when simple unweighted graphs are desired. (Simply ignore
 * edge weights.)
 * 
 * 
 * 
 */
public class SimpleWeightedDigraph extends WeightedDigraph{
	private final boolean allowLoops;

	/**
	 * Constructor for SimpleWeightedDigraph.
	 * 
	 * @param vertexCapacity initially allocate space for this many vertices.
	 * 
	 * @param edgeCapacity initially allocate space for this many edges.
	 * 
	 * @param defaultEdgeWeight edges are given this weight at creation time by default. 
	 * the default is 1.0 for constructors where not specified.
	 * 
	 * @param loopsAllowed Loops are allowed in the graph if this value set true
	 * in constructor. Default value is false.
	 * 
	 * If vertex weights are desired, the class can either be extended or a vertex 
	 * attribute can be defined using the code
	 * DoubleAttribute vertexWeights = 
	 * 		(DoubleAttribute)this.vertexAttributes().createAttribute("weight", AttributeManager.DOUBLE_TYPE);
	 */
	public SimpleWeightedDigraph(int vertexCapacity, int edgeCapacity, double defaultEdgeWeight, boolean loopsAllowed) 
	{
		super( vertexCapacity, edgeCapacity, defaultEdgeWeight );
		allowLoops = loopsAllowed;
	}

	/**
	 * Constructor for SimpleWeightedDigraph. 
	 * 
	 * AllowLoops is false by default.
	 * @param vertexCapacity
	 * @param edgeCapacity
	 * @param defaultEdgeWeight
	 */
	public SimpleWeightedDigraph(int vertexCapacity, int edgeCapacity, double defaultEdgeWeight) 
	{
		super( vertexCapacity, edgeCapacity, defaultEdgeWeight );
		allowLoops = false;
	}

	/**
	 * Constructor for SimpleWeightedDigraph. 
	 * 
	 * AllowLoops is false by default.
	 * The defaultEdgeWeight is 1.0.
	 * @param vertexCapacity
	 * @param edgeCapacity
	 */
	public SimpleWeightedDigraph(int vertexCapacity, int edgeCapacity) 
	{
		super( vertexCapacity, edgeCapacity, 1.0 );
		allowLoops = false;
	}

	/** 
	 * Add an edge with the the default edge weight. 
	 * 
	 * If an edge from and to the vertices
	 * specified by the edge already exists in the graph, 
	 * then the edge weight in increased by the default value.
	 * @param e the edge to add.
	 * @return true if the edge was added sucessfully.
	 */
	@Override
    public boolean add( Edge e )
	{
		if( !allowLoops && (e.from() == e.to()) ) return false;
		Edge[] ft = this.getEdges( e.from() , e.to() );
		if( ft.length == 0 )
		{
			return super.add( e );
		}
		return this.setWeight( ft[0] , this.getWeight( ft[0] ) + this.getDefaultEdgeWeight() );
	}
	/** 
	 * Add an edge with the the specified edge weight. 
	 * 
	 * If an edge from and to the vertices
	 * specified by the edge already exists in the graph,
	 * then the edge weight in increased
	 * by the specified value.
	 * 
	 * @return true if the edge was added sucessfully.
	 */
	@Override
    public boolean add( Edge e, double weight )
	{
		if( !allowLoops && (e.from() == e.to()) ) return false;
		Edge[] ft = this.getEdges( e.from() , e.to() );
		if( ft.length == 0 )
		{
			return super.add( e , weight);
		}
		return this.setWeight( ft[0] , this.getWeight( ft[0] ) + weight );
	}
	
	@Override
    public boolean remove( Edge e )
	{
		Edge[] ft = this.getEdges( e.from() , e.to() );
		if( ft.length == 0 ) {
			return false;
		}
		return super.remove( ft[0] );		
	}
		
	
	@Override
    public double getWeight( Edge e )
	{
		Edge[] ft = this.getEdges( e.from() , e.to() );
		if( ft.length == 0 ) {
			return 0.0;
		}
		return super.getWeight( ft[0] );		
	}
	
	
	@Override
    public DirectedGraph copy()
	{
		SimpleWeightedDigraph copy = new SimpleWeightedDigraph(this.numVertices(), this.numEdges(), this.getDefaultEdgeWeight(), allowLoops);
		copyAll( copy );
		return copy;
	}

}
