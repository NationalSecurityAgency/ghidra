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
package functioncalls.graph;

import java.util.*;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.map.LazyMap;

import functioncalls.plugin.FunctionCallGraphPlugin;
import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.listing.Function;

/**
 * A graph for the {@link FunctionCallGraphPlugin}
 */
public class FunctionCallGraph extends FilteringVisualGraph<FcgVertex, FcgEdge> {

	private VisualGraphLayout<FcgVertex, FcgEdge> layout;
	private FcgVertex source;
	private Map<Function, FcgVertex> verticesByFunction = new HashMap<>();
	private Comparator<FcgVertex> vertexComparator =
		(v1, v2) -> v1.getAddress().compareTo(v2.getAddress());
	private Map<FcgLevel, Set<FcgVertex>> verticesByLevel =
		LazyMap.lazyMap(new HashMap<>(), () -> new TreeSet<>(vertexComparator));

	/**
	 * Sets the source vertex from which the graph is created
	 * @param source the source vertex from which the graph is created
	 */
	public void setSource(FcgVertex source) {
		if (this.source != null) {
			throw new IllegalStateException("Cannot change graph source once it has been created");
		}

		this.source = source;
		addVertex(source);
	}

	/**
	 * Returns the vertex from which the graph is created
	 * @return the vertex from which the graph is created
	 */
	public FcgVertex getSource() {
		return source;
	}

	/**
	 * Returns the vertex mapped to the given function; null if there is no matching vertex
	 * 
	 * @param f the function
	 * @return the vertex
	 */
	public FcgVertex getVertex(Function f) {
		return verticesByFunction.get(f);
	}

	/**
	 * Returns true if this graph contains a vertex for the given function
	 * 
	 * @param f the function 
	 * @return true if this graph contains a vertex for the given function
	 */
	public boolean containsFunction(Function f) {
		return verticesByFunction.containsKey(f);
	}

	/**
	 * Returns all vertices in the given level.  The result will be non-null.
	 * 
	 * @param level the level of the vertices to retrieve
	 * @return all vertices in the given level
	 */
	public Iterable<FcgVertex> getVerticesByLevel(FcgLevel level) {
		return IterableUtils.unmodifiableIterable(verticesByLevel.get(level));
	}

	/**
	 * Returns the largest level (the furthest level from the source node) in the given 
	 * direction 
	 * 
	 * @param direction the direction to search
	 * @return the largest level
	 */
	public FcgLevel getLargestLevel(FcgDirection direction) {

		FcgLevel greatest = new FcgLevel(1, direction);

		Set<FcgLevel> keys = verticesByLevel.keySet();
		for (FcgLevel level : keys) {
			if (level.getDirection() != direction) {
				continue;
			}

			if (level.getRow() > greatest.getRow()) {
				greatest = level;
			}
		}

		return greatest;
	}

	@Override
	public VisualGraphLayout<FcgVertex, FcgEdge> getLayout() {
		return layout;
	}

	@Override
	public FunctionCallGraph copy() {

		FunctionCallGraph newGraph = new FunctionCallGraph();
		for (FcgVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (FcgEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	public void setLayout(VisualGraphLayout<FcgVertex, FcgEdge> layout) {
		this.layout = layout;
	}

	@Override
	protected void verticesAdded(Collection<FcgVertex> added) {
		for (FcgVertex v : added) {
			Function f = v.getFunction();
			verticesByFunction.put(f, v);
			verticesByLevel.get(v.getLevel()).add(v);
		}
		super.verticesAdded(added);
	}

	@Override
	protected void verticesRemoved(Collection<FcgVertex> removed) {
		for (FcgVertex v : removed) {
			Function f = v.getFunction();
			verticesByFunction.remove(f);
			verticesByLevel.get(v.getLevel()).remove(v);
		}
		super.verticesRemoved(removed);
	}

}
