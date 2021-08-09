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
package ghidra.service.graph;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.jgrapht.graph.AbstractBaseGraph;
import org.jgrapht.graph.DefaultGraphType;

/**
 * Basic graph implementation for a directed graph whose vertices and edges support attributes.
 * <P>
 * The graph can be configured as to how to handle multiple edges with the same source and destination
 * vertices. One option is to simply allow multiple edges.  The second option is to collapse 
 * duplicate edges such that there is only ever one edge with the same
 * source and destination.  In this case, each additional duplicate edge added will cause the
 * edge to have a "Weight" attribute that will be the total number of edges that were added
 * to the same source/destination vertex pair. 
 */
public class AttributedGraph extends AbstractBaseGraph<AttributedVertex, AttributedEdge> {
	public static final String WEIGHT = "Weight";

	private Map<String, AttributedVertex> vertexMap = new HashMap<>();
	private final boolean collapseDuplicateEdges;

	private String name;

	private GraphType type;

	private String description;

	/**
	 * Create a new empty AttributedGraph that automatically collapses duplicate edges
	 * 
	 * @param name the name of the graph
	 * @param type the {@link GraphType} which defines valid vertex and edge types.
	 */
	public AttributedGraph(String name, GraphType type) {
		this(name, type, name, true);
	}

	/**
	 * Create a new empty AttributedGraph that automatically collapses duplicate edges
	 * 
	 * @param name the name of the graph
	 * @param type the {@link GraphType} which defines valid vertex and edge types.
	 * @param description a description of the graph
	 */
	public AttributedGraph(String name, GraphType type, String description) {
		this(name, type, description, true);
	}

	/**
	 * Create a new empty AttributedGraph.
	 *
	 * @param name the name of the graph
	 * @param type the {@link GraphType} which defines valid vertex and edge types.
	 * @param description a description of the graph
	 * @param collapseDuplicateEdges if true, duplicate edges will be collapsed into a single
	 * edge with a "Weight" attribute whose value is the number of edges between those vertices.
	 */
	public AttributedGraph(String name, GraphType type, String description,
			boolean collapseDuplicateEdges) {
		super(new VertexSupplier(), new EdgeSupplier(), DefaultGraphType.directedPseudograph());
		this.name = name;
		this.type = type;
		this.description = description;
		this.collapseDuplicateEdges = collapseDuplicateEdges;
	}

	/**
	 * Returns the name of the graph
	 * @return the name of the graph
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a description of the graph
	 * @return a description of the graph
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns the {@link GraphType} for this graph
	 * @return  the {@link GraphType} for this graph
	 */
	public GraphType getGraphType() {
		return type;
	}

	/**
	 * Adds a new vertex with the given id.  The vertex's name will be the same as the id.
	 * If a vertex already exists with that id,
	 * then that vertex will be returned.
	 * 
	 * @param id the unique vertex id that the graph should have a vertex for.
	 * @return either an existing vertex with that id, or a newly added vertex with that id
	 */
	public AttributedVertex addVertex(String id) {
		return addVertex(id, id);
	}

	/**
	 * Adds a new vertex with the given id and name.  If a vertex already exists with that id,
	 * then that vertex will be returned, but with its name changed to the given name.
	 * 
	 * @param id the unique vertex id that the graph should have a vertex for.
	 * @param name the name to associate with this vertex
	 * @return either an existing vertex with that id, or a newly added vertex with that id
	 */
	public AttributedVertex addVertex(String id, String name) {
		if (vertexMap.containsKey(id)) {
			AttributedVertex vertex = vertexMap.get(id);
			vertex.setName(name);
			return vertex;
		}
		AttributedVertex newVertex = new AttributedVertex(id, name);
		addVertex(newVertex);
		return newVertex;
	}

	@Override
	public AttributedVertex addVertex() {
		AttributedVertex vertex = super.addVertex();
		vertexMap.put(vertex.getId(), vertex);
		return vertex;
	}

	@Override
	public boolean addVertex(AttributedVertex vertex) {
		if (super.addVertex(vertex)) {
			vertexMap.put(vertex.getId(), vertex);
			return true;
		}
		return false;
	}

	/**
	 * Creates and adds a new directed edge with the given id between the given source and
	 * target vertices. If the graph is set to collapse duplicate edges and an edge for that
	 * source and target exists, then the existing edge will be return with its "Weight" attribute
	 * set to the total number of edges that have been added between the source and target vertices.
	 * 
	 * @param source the source vertex of the directed edge to be created.
	 * @param target the target vertex of the directed edge to be created.
	 * @param edgeId the id to use for the new edge.  Note: if this is a duplicate and edges
	 * are being collapsed, then this edgeId will not be used.
	 * @return a new edge between the source and target if it is the first one or the graph is
	 * not collapsing edges.  Otherwise, an existing edge with its "Weight" attribute set accordingly.
	 */
	public AttributedEdge addEdge(AttributedVertex source, AttributedVertex target, String edgeId) {
		AttributedEdge basicEdge = new AttributedEdge(edgeId);
		addEdge(source, target, basicEdge);
		return basicEdge;
	}

	/**
	 * Creates and adds a new directed edge with the given edge object. If the graph is set to
	 * collapse duplicate edges and an edge for that
	 * source and target exists, then the existing edge will be return with its "Weight" attribute
	 * set to the total number of edges that have been added between the source and target vertices.
	 * 
	 * @param source the source vertex of the directed edge to be created.
	 * @param target the target vertex of the directed edge to be created.
	 * @param edge the BasicEdge object to use for the new edge.  Note: if this is a duplicate and
	 * edges are being collapsed, then this edge object will not be used.
	 * @return true if the edge was added. Note that if this graph is collapsing duplicate edges, then
	 * it will always return true.
	 */
	@Override
	public boolean addEdge(AttributedVertex source, AttributedVertex target, AttributedEdge edge) {
		ensureInGraph(source);
		ensureInGraph(target);
		if (collapseDuplicateEdges) {
			AttributedEdge existingEdge = getEdge(source, target);
			if (existingEdge != null) {
				incrementWeightProperty(existingEdge);
				return true;
			}
		}
		return super.addEdge(source, target, edge);
	}

	/**
	 * Creates and adds a new directed edge between the given source and
	 * target vertices. If the graph is set to collapse duplicate edges and an edge for that
	 * source and target exists, then the existing edge will be return with its "Weight" attribute
	 * set to the total number of edges that have been added between the source and target vertices.
	 * 
	 * @param source the source vertex of the directed edge to be created.
	 * @param target the target vertex of the directed edge to be created.
	 * @return a new edge between the source and target if it is the first one or the graph is
	 * not collapsing edges.  Otherwise, an existing edge with its "Weight" attribute set accordingly.
	 */
	@Override
	public AttributedEdge addEdge(AttributedVertex source, AttributedVertex target) {
		ensureInGraph(source);
		ensureInGraph(target);

		if (collapseDuplicateEdges) {
			AttributedEdge edge = getEdge(source, target);
			if (edge != null) {
				incrementWeightProperty(edge);
				return edge;
			}
		}
		return super.addEdge(source, target);
	}

	/**
	 * Returns the total number of edges in the graph
	 * @return the total number of edges in the graph
	 */
	public int getEdgeCount() {
		return edgeSet().size();
	}

	/**
	 * Returns the total number of vertices in the graph
	 * @return the total number of vertices in the graph
	 */
	public int getVertexCount() {
		return vertexSet().size();
	}

	/**
	 * Returns the vertex with the given vertex id
	 * @param vertexId the id of the vertex to retrieve
	 * @return  the vertex with the given vertex id or null if none found
	 */
	public AttributedVertex getVertex(String vertexId) {
		return vertexMap.get(vertexId);
	}

	private void ensureInGraph(AttributedVertex vertex) {
		if (!containsVertex(vertex)) {
			addVertex(vertex);
		}
	}

	private static void incrementWeightProperty(AttributedEdge edge) {
		if (edge.hasAttribute(WEIGHT)) {
			String weightString = edge.getAttribute(WEIGHT);
			edge.setAttribute(WEIGHT, incrementWeightStringValue(weightString));
		}
		else {
			edge.setAttribute(WEIGHT, "2");
		}
	}

	private static String incrementWeightStringValue(String value) {
		int weight = Integer.parseInt(value);
		weight++;
		return Integer.toString(weight);
	}

	/**
	 * Default VertexSupplier that uses a simple one up number for default vertex ids
	 */
	private static class VertexSupplier implements Supplier<AttributedVertex> {
		long nextId = 1;

		@Override
		public AttributedVertex get() {
			return new AttributedVertex(Long.toString(nextId++));
		}
	}

	/**
	 * Default EdgeSupplier that uses a simple one up number for default edge ids
	 */
	private static class EdgeSupplier implements Supplier<AttributedEdge> {
		long nextId = 1;

		@Override
		public AttributedEdge get() {
			return new AttributedEdge(Long.toString(nextId++));
		}
	}
}
