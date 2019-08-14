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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;

import javax.swing.Icon;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * A simple layout that is used during testing
 */
public class TestFGLayoutProvider extends FGLayoutProvider {

	private static final String NAME = "Test Layout";
	private static final int VERTEX_TO_EDGE_ARTICULATION_OFFSET = 20;

	@Override
	public String getLayoutName() {
		return NAME;
	}

	@Override
	public Icon getActionIcon() {
		return Icons.ADD_ICON;
	}

	@Override
	public int getPriorityLevel() {
		return 0;
	}

	@Override
	public FGLayout getFGLayout(FunctionGraph graph, TaskMonitor monitor)
			throws CancelledException {
		return new TestFGLayout(graph);
	}

	private class TestFGLayout extends AbstractFGLayout {

		protected TestFGLayout(FunctionGraph graph) {
			super(graph, NAME);
		}

		@Override
		protected AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedFGLayout(
				FunctionGraph newGraph) {
			return new TestFGLayout(newGraph);
		}

		@Override
		protected Point2D getVertexLocation(FGVertex v, Column col, Row<FGVertex> row,
				Rectangle bounds) {
			return getCenteredVertexLocation(v, col, row, bounds);
		}

		@Override
		protected GridLocationMap<FGVertex, FGEdge> performInitialGridLayout(
				VisualGraph<FGVertex, FGEdge> g) throws CancelledException {

			GridLocationMap<FGVertex, FGEdge> gridLocations = new GridLocationMap<>();

			Map<FGVertex, Node> nodesByVertices = new HashMap<>();
			Collection<FGVertex> vertices = g.getVertices();
			List<Node> rows = new ArrayList<>();
			for (FGVertex v : vertices) {
				Node node = new Node(v);
				nodesByVertices.put(v, node);
				rows.add(node);
			}
			Collections.sort(rows,
				(n1, n2) -> n1.v.getVertexAddress().compareTo(n2.v.getVertexAddress()));

			for (int i = 0; i < rows.size(); i++) {
				Node node = rows.get(i);
				node.row = i;
				gridLocations.row(node.v, i);
			}

			FunctionGraph fg = (FunctionGraph) g;
			Address entry = function.getEntryPoint();
			FGVertex source = fg.getVertexForAddress(entry);
			treeify(g, source, nodesByVertices);

			Node node = nodesByVertices.get(source);
			node.col = 1; // start column
			gridLocations.col(source, node.col);
			assignColumns(source, nodesByVertices, gridLocations);

			//Msg.out("grid: " + gridLocations.toStringGrid());

			return gridLocations;
		}

		private void assignColumns(FGVertex source, Map<FGVertex, Node> nodesByVertices,
				GridLocationMap<FGVertex, FGEdge> gridLocations) {

			Node node = nodesByVertices.get(source);
			int parentColumn = node.col;
			if (node.left == null) {
				return; // we assign left first, so it is null, then there is no right
			}

			Node left = node.left;
			Node right = node.right;
			if (alreadyAssigned(node)) {
				return;
			}

			if (left.col == 0) { // not set
				// align the left node directly under the parent
				left.col = parentColumn;
				gridLocations.col(left.v, left.col);
			}

			if (right != null) {
				if (right.col == 0) {
					right.col = parentColumn + 1;
					gridLocations.col(right.v, right.col);
				}

				// descend right then left so that the graph goes to the right and then downward
				assignColumns(node.right.v, nodesByVertices, gridLocations);
			}

			assignColumns(node.left.v, nodesByVertices, gridLocations);
		}

		private boolean alreadyAssigned(Node node) {

			Node left = node.left;
			if (left.col == 0) {
				return false;
			}

			Node right = node.right;
			if (right != null) {
				if (right.col == 0) {
					return false;
				}
			}

			return true;
		}

		private void treeify(VisualGraph<FGVertex, FGEdge> g, FGVertex source,
				Map<FGVertex, Node> nodesByVertices) {

			Collection<FGEdge> outEdges = g.getOutEdges(source);
			Iterator<FGEdge> it = outEdges.iterator();
			Node parent = nodesByVertices.get(source);
			if (parent.processed) {
				return;
			}

			parent.processed = true;
			int n = outEdges.size();
			switch (n) {
				case 0:
					// sink
					break;
				case 1:
					FGEdge e = it.next();
					FGVertex end = e.getEnd();
					Node node = nodesByVertices.get(end);
					parent.left = node;

					treeify(g, end, nodesByVertices);
					break;
				case 2:

					FGEdge e1 = it.next();
					FGEdge e2 = it.next();
					FGVertex end1 = e1.getEnd();
					FGVertex end2 = e2.getEnd();
					Node n1 = nodesByVertices.get(end1);
					Node n2 = nodesByVertices.get(end2);

					FGVertex left;
					FGVertex right;

					// largest row is left; put further away addresses at the bottom
					int comp = n1.row - n2.row;
					if (comp < 0) {
						parent.right = n1;
						parent.left = n2;
						left = end2;
						right = end1;
					}
					else {
						parent.left = n1;
						parent.right = n2;
						left = end1;
						right = end2;
					}

					treeify(g, right, nodesByVertices);
					treeify(g, left, nodesByVertices);
					break;
				default:
					if (!(parent.v instanceof GroupedFunctionGraphVertex)) {
						// this can happen if a test adds another edge to a test vertex
						Msg.debug(this, "\n\n\tMore than 2 edges?: " + parent);
					}

			}
		}

		@Override
		protected Map<FGEdge, List<Point2D>> positionEdgeArticulationsInLayoutSpace(
				VisualGraphVertexShapeTransformer<FGVertex> transformer,
				Map<FGVertex, Point2D> vertexLayoutLocations, Collection<FGEdge> edges,
				LayoutLocationMap<FGVertex, FGEdge> layoutLocations) throws CancelledException {

			Map<FGEdge, List<Point2D>> newEdgeArticulations = new HashMap<>();

			// 
			// Route our edges!
			//
			for (FGEdge e : edges) {
				monitor.checkCanceled();

				FGVertex startVertex = e.getStart();
				FGVertex endVertex = e.getEnd();

				// 
				// TODO For now I will use the layout positions to determine edge type (nested v.
				// fallthrough). It would be nicer if I had this information defined somewhere
				// -->Maybe positioning is simple enough?
				//

				Column startCol = layoutLocations.col(startVertex);
				Column endCol = layoutLocations.col(endVertex);
				Point2D start = vertexLayoutLocations.get(startVertex);
				Point2D end = vertexLayoutLocations.get(endVertex);
				List<Point2D> articulations = new ArrayList<>();

				int direction = 20;
				if (startCol.index < endCol.index) { // going forward on the x-axis
					//  TODO make constant					
//						direction = 10;
				}
				else if (startCol.index > endCol.index) { // going backwards on the x-axis
					direction = -direction;
				}

				int offsetFromVertex = isCondensedLayout()
						? (int) (VERTEX_TO_EDGE_ARTICULATION_OFFSET * (1 - getCondenseFactor()))
						: VERTEX_TO_EDGE_ARTICULATION_OFFSET;

				if (startCol.index < endCol.index) { // going left or right
					//
					// Basic routing: 
					// -leave the bottom of the start vertex
					// -first bend at some constant offset
					// -move to right or left, to above the end vertex
					// -second bend above the end vertex at previous constant offset
					//
					// Advanced considerations:
					// -Remove angles from vertex points:
					// -->Edges start/end on the vertex center.  If we offset them to avoid 
					//    overlapping, then they produce angles when only using two articulations.
					//    Thus, we will create articulations that are behind the vertices to remove
					//    the angles.  This points will not be seen.
					//
					Shape shape = transformer.apply(startVertex);
					Rectangle bounds = shape.getBounds();
					double vertexBottom = start.getY() + (bounds.height >> 1); // location is centered

					double x1 = start.getX() + direction;
					double y1 = start.getY(); // hidden
					articulations.add(new Point2D.Double(x1, y1));

					double x2 = x1;
					double y2 = vertexBottom + offsetFromVertex;
					y2 = end.getY();
					articulations.add(new Point2D.Double(x2, y2));

					double x3 = end.getX() + (-direction);
					double y3 = y2;
					articulations.add(new Point2D.Double(x3, y3));

//						double x4 = x3;
//						double y4 = end.getY(); // hidden
//						articulations.add(new Point2D.Double(x4, y4));
				}

				else if (startCol.index > endCol.index) { // flow return
					e.setDefaultAlpha(.25);

					Shape shape = transformer.apply(startVertex);
					Rectangle bounds = shape.getBounds();
					double vertexBottom = start.getY() + (bounds.height >> 1); // location is centered

					double x1 = start.getX() + (direction);
					double y1 = start.getY(); // hidden
					articulations.add(new Point2D.Double(x1, y1));

					double x2 = x1;
					double y2 = vertexBottom + offsetFromVertex;
					articulations.add(new Point2D.Double(x2, y2));

					double x3 = end.getX() + (-direction);
					double y3 = y2;
					articulations.add(new Point2D.Double(x3, y3));

					double x4 = x3;
					double y4 = end.getY(); // hidden
					articulations.add(new Point2D.Double(x4, y4));
				}

				else {  // same column--nothing to route
					// straight line, which is the default
					e.setDefaultAlpha(.25);
				}
				newEdgeArticulations.put(e, articulations);
			}
			return newEdgeArticulations;
		}
	}

	private class Node {

		private FGVertex v;

		private Node left;
		private Node right;

		private int row;
		private int col;

		private boolean processed;

		Node(FGVertex v) {
			this.v = v;
		}

		@Override
		public String toString() {
			//@formatter:off
			return "{\n" +
				"\tv: " + v + ",\n" +
				"\tleft: " + left + ",\n" +
				"\tright: " + right + "\n" + 
			"}";
			//@formatter:on
		}
	}
}
