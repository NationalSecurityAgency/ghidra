/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.NoValueException;
import ghidra.util.graph.attributes.AttributeManager;
import ghidra.util.graph.attributes.DoubleAttribute;

/**
 * DirectedGraph with edge weights. Weights are assumed to be 0.0 by default.
 * 
 *  
 */
public class WeightedDigraph extends DirectedGraph {
  //private DoubleAttribute weights;
  private double defaultValue = 1.0;

	/** Create weighted directed graph with default edge weight of 0.0
	 * and room for vertexCapicity vertices and edgeCapacity edges.
	 */
  	public WeightedDigraph( int vertexCapacity, int edgeCapacity )
  	{
      	super( vertexCapacity, edgeCapacity );
   	  	this.edgeAttributes().createAttribute( "weight", AttributeManager.DOUBLE_TYPE);       
  	}
  	
  	private DoubleAttribute<Edge> weights()
  	{
  		return (DoubleAttribute<Edge>) this.edgeAttributes().getAttribute("weight");
  	}

  	/** Create a weighted directed graph. Use the defaultEdgeWeight for any edges whose
   	*  weights have not been set. 
   	*/
  	public WeightedDigraph( int vertexCapacity, int edgeCapacity, double defaultEdgeWeight )
  	{
      	super( vertexCapacity, edgeCapacity );
      	defaultValue = defaultEdgeWeight;
   	  	this.edgeAttributes().createAttribute( "weight", AttributeManager.DOUBLE_TYPE);       
  	}

  	/** Default constructor */
  	public WeightedDigraph()
  	{
      	this( 101, 101 );
  	}

	/** Returns the weighted in-degree of this vertex. The in-degree is the
	 * sum of weights of all enges entering this vertex.
	 */
	@Override
    public double inDegree( Vertex v )
	{
      double degree = 0.0;
      Edge[] edges = this.incomingEdges( v );
      int length = edges.length;
      for( int i=0; i< length; i++ )
      {
         try
         {
         	degree += weights().getValue( edges[i] );
         }
         catch( NoValueException exc )
         {
         	degree += defaultValue;
         }
      }
      return degree;
	}
	
	/** Returns the weighted out-degree of this vertex. The out-degree is the
	 * sum of weights of all enges entering this vertex.
	 */
	@Override
    public double outDegree( Vertex v )
	{
      double degree = 0.0;
      Edge[] edges = this.outgoingEdges( v );
      int length = edges.length;
      for( int i=0; i< length; i++ )
      {
         try
         {
         	degree += weights().getValue( edges[i] );
         }
         catch( NoValueException exc )
         {
         	degree += defaultValue;
         }
      }
      return degree;
	}
	
	/** Returns the weighted self-degree of this vertex. The self-degree is the
	 * sum of weights of all loops at this vertex.
	 */
	public double selfDegree( Vertex v )
	{
      double degree = 0.0;
      Edge[] edges = this.selfEdges( v );
      int length = edges.length;
      for( int i=0; i< length; i++ )
      {
         try
         {
         	degree += weights().getValue( edges[i] );
         }
         catch( NoValueException exc )
         {
         	degree += 0.0;
         }
      }
      return degree;
	}
	
	/** Returns the weighted degree of this vertex. The degree is the
	 * sum of weights of all edges entering and leaving this vertex.
	 */
	@Override
    public double degree( Vertex v )
	{
		return inDegree( v ) + outDegree( v ) - selfDegree( v );
	}

	/** Returns the weight of the specified edge.
	 */
	public double getWeight( Edge e )
	{
		try
		{
			return weights().getValue( e );
		}
		catch( NoValueException ex )
		{
			return 0.0;
		}
	}
	
	/** Sets the weight of the specified edge.
	 */
	public boolean setWeight( Edge e, double value )
	{
		return weights().setValue( e, value );
	}	
	
	/** Gets the defaultEdgeWeight of this graph specified at creation
	 * time.
	 */
	public double getDefaultEdgeWeight()
	{
		return defaultValue;
	}
	
	/** Add an edge. If successful (i.e. that edge does not already appear
	 * in the graph), set the weight to the default value
	 * @return true if edge added succesfuly.
	 */
	@Override
    public boolean add( Edge e )
	{
		double wt = getWeight( e );
		boolean returnValue = super.add( e );
		if( returnValue ) 
			setWeight( e, defaultValue );
		else
			setWeight( e, wt + defaultValue );
		return true;
	}
	
	/** Add an edge. If successful (i.e. that edge does not appear in the graph),
	 * then set the weight to the specified value.
	 * 
	 * @return true if edge added succesfuly.
	 */
	public boolean add( Edge e, double weight )
	{
		double wt = getWeight( e );
		super.add( e );
		setWeight( e, wt + weight );
		return true;
	}
	
	/** Get the edge weights for this graph. */
	public DoubleAttribute<Edge> getEdgeWeights()
	{
		return this.weights();
	}
	
	
	@Override
    public DirectedGraph copy()
	{
		WeightedDigraph copy = new WeightedDigraph(this.numVertices(), this.numEdges(), this.getDefaultEdgeWeight());
		copyAll( copy );
		return copy;
	}
	
	
	/** Creates intersection of graphs in place by adding all vertices and edges of
	 * other graph to this graph. This method used to return a different graph
	 * as the intersection but now does not.
	 * 
	 */
	@Override
    public void intersectionWith(DirectedGraph otherGraph) {
		GraphIterator<Vertex> vi = otherGraph.vertexIterator();
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
	@Override
    public void unionWith(DirectedGraph otherGraph) {
		DoubleAttribute<Edge> otherWts = (DoubleAttribute<Edge>) otherGraph.edgeAttributes().getAttribute("weight");
		GraphIterator<Vertex> vi = otherGraph.vertexIterator();
		while (vi.hasNext()) {
			add(vi.next());
		}
		GraphIterator<Edge> ei = otherGraph.edgeIterator();
		while (ei.hasNext()) {
			Edge e = ei.next();
			try {
				add( e , otherWts.getValue( e ));
			} catch (NoValueException e1) {
				add( e );
			}
		}
	}


		
}
