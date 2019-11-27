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
package ghidra.examples.graph.layout;

import java.util.*;

import org.apache.commons.collections4.map.LazyMap;

import ghidra.examples.graph.*;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.GridLocationMap;
import ghidra.util.exception.CancelledException;

/**
 * A custom layout to arrange the plugin vertices of the {@link SampleGraphPlugin}, using
 * the number of dependencies as a guide for arrangement.
 */
public class SampleGraphPluginDependencyLayout
		extends AbstractVisualGraphLayout<SampleVertex, SampleEdge> {

	protected SampleGraphPluginDependencyLayout(SampleGraph graph, String name) {
		super(graph, name);
	}

	@Override
	public SampleGraph getVisualGraph() {
		return (SampleGraph) getGraph();
	}

	@Override
	public AbstractVisualGraphLayout<SampleVertex, SampleEdge> createClonedLayout(
			VisualGraph<SampleVertex, SampleEdge> newGraph) {
		if (!(newGraph instanceof SampleGraph)) {
			throw new IllegalArgumentException("Must pass a " + SampleGraph.class.getSimpleName() +
				"to clone the " + getClass().getSimpleName());
		}

		SampleGraphPluginDependencyLayout newLayout =
			new SampleGraphPluginDependencyLayout((SampleGraph) newGraph, getLayoutName());
		return newLayout;
	}

	@Override
	protected GridLocationMap<SampleVertex, SampleEdge> performInitialGridLayout(
			VisualGraph<SampleVertex, SampleEdge> g) throws CancelledException {

		GridLocationMap<SampleVertex, SampleEdge> results = new GridLocationMap<>();
		Collection<SampleVertex> vertices = g.getVertices();

		// 
		// Organize vertices by layer, where they are stratified by the number of incoming
		// connections
		//

		Map<Integer, List<SampleVertex>> verticesByRow =
			LazyMap.lazyMap(new HashMap<>(), () -> new LinkedList<>());

		for (SampleVertex v : vertices) {
			Collection<SampleEdge> in = g.getInEdges(v);
			Collection<SampleEdge> out = g.getOutEdges(v);
			int edgeCount = out.size() + in.size();
			verticesByRow.get(edgeCount).add(v);
		}

		//
		// Organize each row alphabetically.  Deal with the last row in a special manner.  
		// (There are so many plugins with no incoming or outgoing dependencies that the row
		// would very long).  
		//
		int rows = verticesByRow.size();
		VertexNameComparator comparator = new VertexNameComparator();

		//@formatter:off
		int longestRow = verticesByRow
				.entrySet()
				.stream()
				.filter(e -> e.getKey() != 0) // 0 has the most vertices; we will handle them later
				.map(e -> e.getValue())
				.mapToInt(l -> l.size())
				.reduce(0, (i1, i2) -> Math.max(i1, i2))
				;
		//@formatter:on

		List<Integer> rowValues = new ArrayList<>(verticesByRow.keySet());
		Collections.sort(rowValues);

		// reverse to put most used on top; ignore last row, as we will handle it later
		for (int i = rowValues.size() - 1; i > 0; i--) {
			Integer row = rowValues.get(i);
			List<SampleVertex> rowVertices = verticesByRow.get(row);

			Collections.sort(rowVertices, comparator);

			int columnCount = rowVertices.size();
			int col = ((longestRow - columnCount) / 2); // center column

			for (int j = 0; j < columnCount; j++) {
				SampleVertex v = rowVertices.get(j);
				int reverseRow = rows - i - 1; // -1 for 0-based
				results.set(v, reverseRow, col++);
			}
		}

		//
		// Now deal with the last row.   Group the last row into many smaller rows, as there
		// are so many.  Offset the vertices so that these rows are indented in front and back.
		//
		int indent = 8; // arbitrary; trial-and-error
		int limit = longestRow - indent;
		List<SampleVertex> lastRow = verticesByRow.get(0); // 0 since they have no edges
		Collections.sort(lastRow, comparator);
		int start = indent / 2;
		int col = start;
		int currentRow = rows + 4; // +4 to create space between these and those above
		for (int i = 0; i < lastRow.size(); i++) {

			SampleVertex v = lastRow.get(i);
			results.set(v, currentRow, col);

			col++;

			// reset for the 
			if ((col - start) == limit) {
				// reset for next row
				col = start;
				currentRow++;
			}
		}

		return results;
	}

	private class VertexNameComparator implements Comparator<SampleVertex> {

		@Override
		public int compare(SampleVertex o1, SampleVertex o2) {
			return o1.getName().compareToIgnoreCase(o2.getName());
		}

	}
}
