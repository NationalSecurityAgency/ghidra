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
package functioncalls.graph.layout;

import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.stream.Collectors;

import functioncalls.graph.*;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A layout that will arrange vertices around a single vertex, with the incoming and outgoing
 * vertices above and below the source vertex, respectively.
 * 
 * <p>The result will look loosely like this:
 * <pre>
 *                   In1    In2   In3
 *                      \    |    /
 *                       \   |   /
 *                           V
 *                         / |  \
 *                        /  |   \
 *                  Out1    Out2  Out3
 * 
 * </pre>
 */
public class BowTieLayout extends AbstractVisualGraphLayout<FcgVertex, FcgEdge> {

	protected BowTieLayout(FunctionCallGraph graph, String name) {
		super(graph, name);
	}

	@Override
	public AbstractVisualGraphLayout<FcgVertex, FcgEdge> createClonedLayout(
			VisualGraph<FcgVertex, FcgEdge> newGraph) {

		if (!(newGraph instanceof FunctionCallGraph)) {
			throw new IllegalArgumentException(
				"Must pass a " + FunctionCallGraph.class.getSimpleName() + "to clone the " +
					getClass().getSimpleName());
		}

		BowTieLayout newLayout = new BowTieLayout((FunctionCallGraph) newGraph, getLayoutName());
		return newLayout;
	}

	@Override
	protected Point2D getVertexLocation(FcgVertex v, Column col, Row<FcgVertex> row,
			Rectangle bounds) {
		return getCenteredVertexLocation(v, col, row, bounds);
	}

	@Override
	public boolean isCondensedLayout() {
		// TODO revisit; condensing looks odd with only one column, as it is not centered; 
		//      try some real data and maybe set condensed based upon how many columns are 
		//      present?  When not condensed, the width of each cell will be that of the largest
		//      column, which means a really long name could cause normally-sized names to 
		//      consume way more space than is needed
//		return false;
		return true; // not sure about this
	}

	@Override
	public FunctionCallGraph getVisualGraph() {
		return (FunctionCallGraph) getGraph();
	}

	@Override
	protected GridLocationMap<FcgVertex, FcgEdge> performInitialGridLayout(
			VisualGraph<FcgVertex, FcgEdge> g) throws CancelledException {

		if (!(g instanceof FunctionCallGraph)) {
			throw new IllegalArgumentException(
				"This layout can only be used with the " + FunctionCallGraph.class);
		}

		return layoutFunctionCallGraph((FunctionCallGraph) g);
	}

	@Override
	public LayoutPositions<FcgVertex, FcgEdge> calculateLocations(VisualGraph<FcgVertex, FcgEdge> g,
			TaskMonitor taskMonitor) {

		LayoutPositions<FcgVertex, FcgEdge> locs = super.calculateLocations(g, taskMonitor);

		// TODO put x offset manipulation here...
		//          -if the number of vertices in each row is not the same odd/even as the 
		//           largest row, then slide the x values for each vertex in the row left or 
		//           right as needed

		return locs;
	}

	private GridLocationMap<FcgVertex, FcgEdge> layoutFunctionCallGraph(FunctionCallGraph g) {

		GridLocationMap<FcgVertex, FcgEdge> grid = new GridLocationMap<>();

		FcgVertex source = Objects.requireNonNull(g.getSource());

		//
		// Incoming nodes on top
		// 	-sorted by address
		//
		List<FcgEdge> inEdges = new ArrayList<>(g.getInEdges(source));
		List<FcgVertex> inVertices =
			inEdges.stream().map(e -> e.getStart()).collect(Collectors.toList());
		inVertices.sort((v1, v2) -> v1.getAddress().compareTo(v2.getAddress()));
		int row = 0; // first row
		for (int col = 0; col < inVertices.size(); col++) {
			FcgVertex v = inVertices.get(col);
			grid.set(v, row, col);
		}

		//
		// Source node
		//
		row = 1; // middle row
		grid.set(source, row, 0);

		// Outgoing nodes on the bottom
		// 	-sorted by address
		// 
		List<FcgEdge> outEdges = new ArrayList<>(g.getOutEdges(source));
		List<FcgVertex> outVertices =
			outEdges.stream().map(e -> e.getEnd()).collect(Collectors.toList());

		// leave already processed vertices in the top row; this can happen if the in vertex is
		// also called by the source function, creating a cycle
		outVertices.removeAll(inVertices);
		outVertices.sort((v1, v2) -> v1.getAddress().compareTo(v2.getAddress()));
		row = 2; // last
		for (int col = 0; col < outVertices.size(); col++) {
			FcgVertex v = outVertices.get(col);
			grid.set(v, row, col);
		}

		grid.centerRows();

		return grid;
	}
}
