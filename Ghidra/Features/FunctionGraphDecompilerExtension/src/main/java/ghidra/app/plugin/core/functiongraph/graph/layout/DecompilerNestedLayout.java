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

import static ghidra.program.model.pcode.PcodeBlock.*;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import org.apache.commons.collections4.map.LazyMap;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.DNLArticulatedEdgeTransformer;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A layout that uses the decompiler to show code nesting based upon conditional logic.
 *
 * <p>Edges returning to the default code flow are painted lighter to de-emphasize them.  This
 * could be made into an option.
 *
 * <p>Edge routing herein defaults to 'simple routing'; 'complex routing' is a user option.
 * Simple routing will reduce edge noise as much as possible by combining/overlapping edges that
 * flow towards the bottom of the function (returning code flow).  Also, edges may fall behind
 * vertices for some functions.   Complex routing allows the user to visually follow the flow
 * of an individual edge.  Complex routing will prevent edges from overlapping and will route
 * edges around vertices.    Simple routing is better when the layout of the vertices is
 * important to the user; complex routing is better when edges/relationships are more
 * important to the user.
 *
 * TODO ideas:
 * -paint fallthrough differently for all, or just for those returning to the baseline
 */
public class DecompilerNestedLayout extends AbstractFGLayout {

	/** Amount of visual buffer between edges and other things used to show separation */
	private static final int EDGE_SPACING = 5;

	/** The space between an articulation point and its vertex */
	private static final int VERTEX_TO_EDGE_ARTICULATION_PADDING = 20;

	private static final int VERTEX_TO_EDGE_AVOIDANCE_PADDING =
		VERTEX_TO_EDGE_ARTICULATION_PADDING - EDGE_SPACING;

	/** Multiplier used to grow spacing as distance between two edge endpoints grows */
	private static final int EDGE_ENDPOINT_DISTANCE_MULTIPLIER = 20;

	/** Amount to keep an edge away from the bounding box of a vertex */
	private static final int VERTEX_BORDER_THICKNESS = EDGE_SPACING;

	/** An amount by which edges entering a vertex from the left are offset to avoid overlapping */
	private static final int EDGE_OFFSET_INCOMING_FROM_LEFT = EDGE_SPACING;

	private DecompilerBlockGraph blockGraphRoot;

	public DecompilerNestedLayout(FunctionGraph graph, String name) {
		this(graph, name, true);
	}

	private DecompilerNestedLayout(FunctionGraph graph, String name, boolean initialize) {
		super(graph, name);
		if (initialize) {
			initialize();
		}
	}

	@Override
	public Function<FGEdge, Shape> getEdgeShapeTransformer() {
		return new DNLArticulatedEdgeTransformer();
	}

	@Override
	public EdgeLabel<FGVertex, FGEdge> getEdgeLabelRenderer() {
		return new DNLEdgeLabelRenderer<>(getCondenseFactor());
	}

	@Override
	protected void condenseEdges(List<Row<FGVertex>> rows,
			Map<FGEdge, List<Point2D>> newEdgeArticulations, double centerX, double centerY) {
		// do not condense, as we route our edges at the preferred positions
	}

	@Override
	protected double getCondenseFactor() {
		// our layout needs more spacing because we have custom edge routing that we want to
		// stand out
		return .3;
	}

	private DNLayoutOptions getLayoutOptions() {
		return (DNLayoutOptions) options.getLayoutOptions(getLayoutName());
	}

	@Override
	protected GridLocationMap<FGVertex, FGEdge> performInitialGridLayout(
			VisualGraph<FGVertex, FGEdge> jungGraph) throws CancelledException {

		BlockGraph outgraph = null;
		DecompileOptions decompilerOptions = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		try {
			ifc.setOptions(decompilerOptions);

			FGVertex aVertex = jungGraph.getVertices().iterator().next();
			Program program = aVertex.getProgram();
			if (!ifc.openProgram(program)) {
				throw new RuntimeException("Unable to initialize: " + ifc.getLastMessage());
			}

			BlockGraph ingraph = buildCurrentFunctionGraph(program, jungGraph, monitor);
			if (ingraph == null) {
				throw new RuntimeException("Unable to initialize: " + ifc.getLastMessage());
			}

			outgraph = ifc.structureGraph(ingraph, program.getAddressFactory(), 0, monitor);
		}
		finally {
			ifc.dispose();
		}

		if (outgraph == null) {
			throw new RuntimeException("No results from the Decompiler: " + ifc.getLastMessage());
		}

		if (outgraph.getSize() == 0) {
			throw new RuntimeException("No results from the Decompiler: " + ifc.getLastMessage());
		}

		blockGraphRoot = new DecompilerBlockGraph(null, outgraph);

		printGraphStrucure(outgraph);
		debug("\n\n");
		printParts(0, outgraph);
		debug("\n\n");
		printConvertedStructure(0, blockGraphRoot);

		GridLocationMap<FGVertex, FGEdge> gridLocations =
			assignCoordinates(jungGraph, blockGraphRoot);

		labelEdges(jungGraph, gridLocations, blockGraphRoot);

		Address entryPoint = function.getEntryPoint();
		FGVertex vertex = getVertex(jungGraph, entryPoint);
		Integer row = gridLocations.row(vertex);
		Integer col = gridLocations.col(vertex);
		if (row != 0 || col != 0) {
			Msg.debug(this, "Function graph has entry point not at top of layout: " + entryPoint);
		}

		return gridLocations;
	}

	private void labelEdges(VisualGraph<FGVertex, FGEdge> jungGraph,
			GridLocationMap<FGVertex, FGEdge> gridLocations, DecompilerBlockGraph root) {

		Collection<FGEdge> edges = jungGraph.getEdges();
		for (FGEdge e : edges) {

			FGVertex start = e.getStart();
			FGVertex end = e.getEnd();
			Address startAddress = start.getVertexAddress();
			Address endAddress = end.getVertexAddress();
			int result = startAddress.compareTo(endAddress);
			DecompilerBlock endBlock = blockGraphRoot.getBlock(end);
			DecompilerBlock loop = endBlock.getParentLoop();
			if (result > 0 && loop != null) {
				DecompilerBlock startBlock = root.getBlock(start);
				startBlock = startBlock.parent;
				e.setLabel(startBlock.getName());
				continue;
			}

			//
			// Special case: fallthrough--don't label this...not sure how to tell fallthrough.  For
			//               now assume that any column below or backwards is fallthrough.  However,
			//               do label fallthrough if it is the only edge.
			//
			Integer startCol = gridLocations.col(start);
			Integer endCol = gridLocations.col(end);
			boolean isFallthrough = startCol >= endCol;

			Collection<FGEdge> outEdges = jungGraph.getOutEdges(start);
			boolean hasBranching = outEdges.size() > 1;

			if (isFallthrough && hasBranching) {
				continue;
			}

			DecompilerBlock startBlock = root.getBlock(start);
			startBlock = startBlock.parent;
			e.setLabel(startBlock.getName());
		}
	}

	@Override
	protected Map<FGEdge, List<Point2D>> positionEdgeArticulationsInLayoutSpace(
			VisualGraphVertexShapeTransformer<FGVertex> transformer,
			Map<FGVertex, Point2D> vertexLayoutLocations, Collection<FGEdge> edges,
			LayoutLocationMap<FGVertex, FGEdge> layoutToGridMap) throws CancelledException {

		Map<FGEdge, List<Point2D>> newEdgeArticulations = new HashMap<>();

		// Condensing Note: we have guilty knowledge that our parent class my condense the
		// vertices and edges towards the center of the graph after we calculate positions.
		// To prevent the edges from moving to far behind the vertices, we will compensate a
		// bit for that effect using this offset value.   The getEdgeOffset() method below is
		// updated for the condense factor.
		int edgeOffset = isCondensedLayout()
				? (int) (VERTEX_TO_EDGE_ARTICULATION_PADDING * (1 - getCondenseFactor()))
				: VERTEX_TO_EDGE_ARTICULATION_PADDING;
		Vertex2dFactory vertex2dFactory =
			new Vertex2dFactory(transformer, vertexLayoutLocations, layoutToGridMap, edgeOffset);

		//
		// Route our edges!
		//
		for (FGEdge e : edges) {
			monitor.checkCanceled();

			FGVertex startVertex = e.getStart();
			FGVertex endVertex = e.getEnd();

			Vertex2d start = vertex2dFactory.get(startVertex);
			Vertex2d end = vertex2dFactory.get(endVertex);
			boolean goingUp = start.rowIndex > end.rowIndex;

			if (goingUp) {
				// we paint loops going back up differently than other edges so the user can
				// visually pick out the loops much easier
				DecompilerBlock block = blockGraphRoot.getBlock(endVertex);
				DecompilerBlock loop = block.getParentLoop();

				if (loop != null) {
					List<Point2D> articulations =
						routeUpwardLoop(layoutToGridMap, vertex2dFactory, start, end, loop);
					newEdgeArticulations.put(e, articulations);
					continue;
				}
			}

			List<Point2D> articulations = new ArrayList<>();

			//
			// Basic routing:
			// -leave the bottom of the start vertex
			// -first bend at some constant offset
			// -move to right or left, to above the end vertex
			// -second bend above the end vertex at previous constant offset
			//
			// Edges start/end on the vertex center.  If we offset them to avoid
			//    overlapping, then they produce angles when only using two articulations.
			//    Thus, we create articulations that are behind the vertices to remove
			//    the angles.  This points will not be seen.
			//
			//
			// Complex routing:
			// -this mode will route edges around vertices
			//
			// One goal for complex edge routing is to prevent overlapping (simple edge routing
			// prefers overlapping to reduce lines).  To prevent overlapping we will use different
			// offset x and y values, depending upon the start and end vertex row and column
			// locations.   Specifically, for a given edge direction there will be a bias:
			// 		-Edge to the right - leave from the right; arrive to the left
			//  	-Edge to the left - leave from the left; arrive to the right
			//  	-Edge straight down - go straight down
			//
			// For each of the above offsets, there will be an amplifier based upon row/column
			// distance from start to end vertex.  This has the effect that larger vertex
			// distances will have a larger offset/spacing.
			//

			if (start.columnIndex < end.columnIndex) { // going to the right

				routeToTheRight(start, end, vertex2dFactory, articulations);
			}

			else if (start.columnIndex > end.columnIndex) { // going to the left; flow return

				// check for the up or down direction
				if (start.rowIndex < end.rowIndex) { // down
					routeToTheLeft(start, end, e, vertex2dFactory, articulations);
				}
				else {
					routeToTheRightGoingUpwards(start, end, vertex2dFactory, articulations);
				}
			}

			else {  // going down; no nesting; flow return

				routeDownward(start, end, e, vertex2dFactory, articulations);
			}

			newEdgeArticulations.put(e, articulations);
		}

		vertex2dFactory.dispose();
		return newEdgeArticulations;
	}

	private List<Point2D> routeUpwardLoop(LayoutLocationMap<FGVertex, FGEdge> layoutToGridMap,
			Vertex2dFactory vertex2dFactory, Vertex2d start, Vertex2d end, DecompilerBlock loop) {
		Set<FGVertex> loopVertices = loop.getVertices();
		FGVertex rightmostLoopVertex =
			getRightmostVertex(layoutToGridMap, vertex2dFactory, loopVertices);

		int startRow = start.rowIndex;
		int endRow = end.rowIndex;
		int startColumn = Math.min(start.columnIndex, end.columnIndex);
		int endColumn = Math.max(start.columnIndex, end.columnIndex);

		Column rightmostLoopColumn = layoutToGridMap.col(rightmostLoopVertex);
		endColumn = Math.max(endColumn, rightmostLoopColumn.index);

		// Look for any vertices that are no part of the loop, but are placed inside
		// of the loop bounds.  This can happen in a graph when the decompiler uses
		// goto statements.   Use the loop's rightmost vertex to establish the loops
		// right edge and then use that to check for any stray non-loop vertices.
		List<Vertex2d> interlopers =
			getVerticesInBounds(vertex2dFactory, startRow, endRow, startColumn, endColumn);

		// place the right x position to the right of the rightmost vertex, not
		// extending past the next column
		FGVertex rightmostVertex = getRightmostVertex(interlopers);
		Column rightmostColumn = layoutToGridMap.col(rightmostVertex);
		Column nextColumn = layoutToGridMap.nextColumn(rightmostColumn);
		Vertex2d rightmostV2d = vertex2dFactory.get(rightmostVertex);

		// the padding used for these two lines is somewhat arbitrary and may be changed
		double rightSide = rightmostV2d.getRight() + GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING;
		double x = Math.min(rightSide,
			nextColumn.x - GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED);

		List<Point2D> articulations = routeLoopEdge(start, end, x);
		return articulations;
	}

	private List<Vertex2d> getVerticesInBounds(Vertex2dFactory vertex2dFactory, int startRow,
			int endRow, int startColumn, int endColumn) {

		if (startRow > endRow) { // going upwards
			int temp = endRow;
			endRow = startRow;
			startRow = temp;
		}

		List<Vertex2d> toCheck = new LinkedList<>();
		for (int row = startRow; row < endRow + 1; row++) {

			for (int col = startColumn; col < endColumn + 1; col++) {

				// assume any other vertex in our column can clip (it will not clip when
				// the 'spacing' above pushes the edge away from this column, like for
				// large row delta values)
				Vertex2d otherVertex = vertex2dFactory.get(row, col);
				if (otherVertex != null) {
					toCheck.add(otherVertex);
				}
			}
		}

		return toCheck;
	}

	private void routeToTheRightGoingUpwards(Vertex2d start, Vertex2d end,
			Vertex2dFactory vertex2dFactory, List<Point2D> articulations) {

		//
		// For routing to the right and back up we will leave the start vertex from the right side
		// and enter the end vertex on the right side.   As the vertices get further apart, we will
		// space them further in towards the center.
		//

		int delta = start.rowIndex - end.rowIndex;
		int multiplier = EDGE_ENDPOINT_DISTANCE_MULTIPLIER;
		if (useSimpleRouting()) {
			multiplier = 1; // we allow edges to overlap with 'simple routing'
		}
		int distanceSpacing = delta * multiplier;

		// Condensing is when the graph will pull nodes closer together on the x axis to
		// reduce whitespace and make the entire graph easier to see.   In this case, update
		// the offset to avoid running into the moved vertices.

		// Condensing Note: we have guilty knowledge that our parent class my condense the
		// vertices and edges towards the center of the graph after we calculate positions.
		// To prevent the edges from moving to far behind the vertices, we will compensate a
		// bit for that effect using this offset value.   The getEdgeOffset() method is
		// updated for the condense factor.

		int exaggerationFactor = 1;
		if (isCondensedLayout()) {
			exaggerationFactor = 2; // determined by trial-and-error; can be made into an option
		}
		distanceSpacing *= exaggerationFactor;

		double x1 = start.getX();
		double y1 = start.getTop() + VERTEX_BORDER_THICKNESS;

		// spacing moves closer to center as the distance grows
		y1 += distanceSpacing;

		// restrict y from moving past the center
		double startCenterY = start.getY() - VERTEX_BORDER_THICKNESS;
		y1 = Math.min(y1, startCenterY);
		articulations.add(new Point2D.Double(x1, y1)); // point is hidden behind the vertex

		// Use the spacing to move the y value towards the top of the vertex.  Just like with
		// the x value, restrict the y to the range between the edge and the center.
		double startRightX = start.getRight();
		double x2 = startRightX + VERTEX_BORDER_THICKNESS; // start at the end

		// spacing moves closer to center as the distance grows
		x2 += distanceSpacing;

		double y2 = y1;
		articulations.add(new Point2D.Double(x2, y2));

		routeAroundColumnVertices(start, end, vertex2dFactory, articulations, x2);

		double x3 = x2;
		double y3 = end.getBottom() - VERTEX_BORDER_THICKNESS;

		// spacing moves closer to center as the distance grows
		y3 -= distanceSpacing;

		// restrict from moving back past the center
		double endYLimit = end.getY() + VERTEX_BORDER_THICKNESS;
		y3 = Math.max(y3, endYLimit);
		articulations.add(new Point2D.Double(x3, y3));

		double x4 = end.getX();
		double y4 = y3;
		articulations.add(new Point2D.Double(x4, y4)); // point is hidden behind the vertex
	}

	private void routeDownward(Vertex2d start, Vertex2d end, FGEdge e,
			Vertex2dFactory vertex2dFactory, List<Point2D> articulations) {

		lighten(e);

		int delta = end.rowIndex - start.rowIndex;
		int distanceSpacing = delta * EDGE_ENDPOINT_DISTANCE_MULTIPLIER;

		double x1 = start.getX() - distanceSpacing; // update for extra spacing
		double y1 = start.getY(); // hidden
		articulations.add(new Point2D.Double(x1, y1));

		double x2 = x1; // same distance over
		double y2 = end.getY();
		articulations.add(new Point2D.Double(x2, y2));

		double x3 = end.getX() + (-distanceSpacing);
		double y3 = y2;

		routeAroundColumnVertices(start, end, vertex2dFactory, articulations, x3);

		articulations.add(new Point2D.Double(x3, y3));

		double x4 = end.getX();
		double y4 = y3;
		articulations.add(new Point2D.Double(x4, y4)); // point is hidden behind the vertex

	}

	private void routeToTheLeft(Vertex2d start, Vertex2d end, FGEdge e,
			Vertex2dFactory vertex2dFactory, List<Point2D> articulations) {

		lighten(e);

		//
		// For routing to the left we will leave the start vertex from just left of center and
		// enter the end vertex on the top, towards the right.   As the vertices get further apart,
		// we will space them further in towards the center of the end vertex.  This will keep
		// edges with close endpoints from intersecting edges with distant endpoints.
		//

		int delta = end.rowIndex - start.rowIndex;
		int multiplier = EDGE_ENDPOINT_DISTANCE_MULTIPLIER;
		if (useSimpleRouting()) {
			multiplier = 1; // we allow edges to overlap with 'simple routing'
		}
		int distanceSpacing = delta * multiplier;

		double x1 = start.getX() - VERTEX_BORDER_THICKNESS; // start at the center

		// spacing moves closer to left edge as the distance grows
		x1 -= distanceSpacing;

		// restrict from moving backwards past the edge
		double startXLimit = start.getLeft() + VERTEX_BORDER_THICKNESS;
		x1 = Math.max(x1, startXLimit);

		// restrict x from moving past the end vertex x value to force the edge to enter
		// from the side
		double endRightX = end.getRight() - VERTEX_BORDER_THICKNESS;
		x1 = Math.max(x1, endRightX);

		double y1 = start.getY();
		articulations.add(new Point2D.Double(x1, y1)); // point is hidden behind the vertex

		double x2 = x1;
		double y2 = start.getBottom() + start.getEdgeOffset();
		articulations.add(new Point2D.Double(x2, y2)); // out of the bottom of the vertex

		// Use the spacing to move the end x value towards the center of the vertex
		double x3 = endRightX - VERTEX_BORDER_THICKNESS; // start at the end			

		// spacing moves closer to center as the distance grows
		x3 -= distanceSpacing;

		// restrict x from moving past the end vertex center x
		int edgeOffset = 0;
		if (usesEdgeArticulations()) {
			// for now, only offset edge lines when we are performing complex routing
			edgeOffset = EDGE_OFFSET_INCOMING_FROM_LEFT;
		}
		double endXLimit = end.getX() + VERTEX_BORDER_THICKNESS + edgeOffset;
		x3 = Math.max(x3, endXLimit);
		double y3 = y2;
		articulations.add(new Point2D.Double(x3, y3)); // into the top of the end vertex

		routeAroundColumnVertices(start, end, vertex2dFactory, articulations, x3);

		double x4 = x3;
		double y4 = end.getY();
		articulations.add(new Point2D.Double(x4, y4)); // point is hidden behind the vertex
	}

	private void routeToTheRight(Vertex2d start, Vertex2d end, Vertex2dFactory vertex2dFactory,
			List<Point2D> articulations) {

		//
		// For routing to the right we will leave the start vertex from the right side and
		// enter the end vertex on the left side.   As the vertices get further apart, we will
		// space them further in towards the center.  This will keep edges with close endpoints
		// from intersecting edges with distant endpoints.
		//

		int delta = end.rowIndex - start.rowIndex;
		if (delta < 0) {
			delta = -delta; // going up
		}
		int multiplier = EDGE_ENDPOINT_DISTANCE_MULTIPLIER;
		if (useSimpleRouting()) {
			multiplier = 1; // we allow edges to overlap with 'simple routing'
		}
		int distanceSpacing = delta * multiplier;

		double startRightX = start.getRight();
		double x1 = startRightX - VERTEX_BORDER_THICKNESS; // start at the end

		// spacing moves closer to center as the distance grows
		x1 -= distanceSpacing;

		// restrict x from moving past the end vertex x value to force the edge to enter
		// from the side
		double endLeftX = end.getLeft() - end.getEdgeOffset();
		x1 = Math.min(x1, endLeftX);

		// restrict from moving backwards past the center
		double startXLimit = start.getX() + VERTEX_BORDER_THICKNESS;
		x1 = Math.max(x1, startXLimit);

		double y1 = start.getY();
		articulations.add(new Point2D.Double(x1, y1)); // point is hidden behind the vertex

		// Use the spacing to move the y value towards the top of the vertex.  Just like with
		// the x value, restrict the y to the range between the edge and the center.
		double x2 = x1;
		double y2 = end.getTop() + VERTEX_BORDER_THICKNESS;

		// spacing moves closer to center as the distance grows
		y2 += distanceSpacing;

		// restrict from moving forwards past the center
		double endYLimit = end.getY() - VERTEX_BORDER_THICKNESS;
		y2 = Math.min(y2, endYLimit);
		articulations.add(new Point2D.Double(x2, y2));

		routeAroundColumnVertices(start, end, vertex2dFactory, articulations, x2);

		double x3 = x2;
		double y3 = end.getY();
		articulations.add(new Point2D.Double(x3, y3)); // point is hidden behind the vertex

		double x4 = end.getX();
		double y4 = y3;
		articulations.add(new Point2D.Double(x4, y4)); // point is hidden behind the vertex
	}

	private void routeAroundColumnVertices(Vertex2d start, Vertex2d end,
			Vertex2dFactory vertex2dFactory, List<Point2D> articulations, double edgeX) {

		if (useSimpleRouting()) {
			return;
		}

		boolean goingDown = true;
		int startRow = start.rowIndex;
		int endRow = end.rowIndex;
		if (startRow > endRow) { // going upwards
			goingDown = false;
			endRow = start.rowIndex;
			startRow = end.rowIndex;
		}

		int startColumn = Math.min(start.columnIndex, end.columnIndex);
		int endColumn = Math.max(start.columnIndex, end.columnIndex);
		if (goingDown) {
			endRow -= 1;
			endColumn -= 1;

			if (start.columnIndex <= end.columnIndex) {
				startRow += 1;
			}
		}
		else {
			// going up we swing out to the right; grab the column that is out to the right
			Column rightColumn = vertex2dFactory.getColumn(edgeX);
			endColumn = rightColumn.index;
		}

		List<Vertex2d> toCheck = new LinkedList<>();
		for (int row = startRow; row < endRow + 1; row++) {

			for (int col = startColumn; col < endColumn + 1; col++) {

				// assume any other vertex in our column can clip (it will not clip when
				// the 'spacing' above pushes the edge away from this column, like for
				// large row delta values)
				Vertex2d otherVertex = vertex2dFactory.get(row, col);
				if (otherVertex != null) {
					toCheck.add(otherVertex);
				}
			}
		}

		// always process the vertices from the start vertex so that the articulation adjustments
		// are correct
		if (!goingDown) {
			Collections.reverse(toCheck);
		}

		int delta = endRow - startRow;
		for (Vertex2d otherVertex : toCheck) {

			int padding = VERTEX_TO_EDGE_AVOIDANCE_PADDING;
			int distanceSpacing = padding + delta; // adding the delta makes overlap less likely

			// Condensing is when the graph will pull nodes closer together on the x axis to
			// reduce whitespace and make the entire graph easier to see.   In this case, update
			// the offset to avoid running into the moved vertices.

			// Condensing Note: we have guilty knowledge that our parent class my condense the
			// vertices and edges towards the center of the graph after we calculate positions.
			// To prevent the edges from moving to far behind the vertices, we will compensate a
			// bit for that effect using this offset value.   The getEdgeOffset() method is
			// updated for the condense factor.

			int vertexToEdgeOffset = otherVertex.getEdgeOffset();
			int exaggerationFactor = 1;
			if (isCondensedLayout()) {
				exaggerationFactor = 4; // determined by trial-and-error; can be made into an option
			}

			double centerX = otherVertex.getX();
			boolean goingLeft = edgeX < centerX;

			if (!goingDown) {
				// for now, any time an edge goes up, we route it to the right
				goingLeft = false;
			}

			VertexClipper vertexClipper = new VertexClipper(goingLeft, goingDown);

			// no need to check the 'y' value, as the end vertex is above/below this one
			if (vertexClipper.isClippingX(otherVertex, edgeX)) {

				/*
					 Must route around this vertex - new points:
					 -p1 - just above the intersection point
					 -p2 - just past the left edge
					 -p3 - just past the bottom of the vertex
					 -p4 - back at the original x value
				
					 	   |
					   .___|
					   | .-----.
					   | |     |
					   | '-----'
					   '---.
					   	   |
				*/

				// p1 - same x; y just above vertex
				double x = edgeX;
				double y = vertexClipper.getTopOffset(otherVertex, vertexToEdgeOffset);
				articulations.add(new Point2D.Double(x, y));

				// Maybe merge points if they are too close together.  Visually, many lines
				// moving around intersecting vertices looks busy.  When the intersecting
				// vertices are close together, we remove some of the articulations in order to
				// smooth out the edges.
				if (articulations.size() > 2) {

					/*
						The last articulation is the one added before this method was called, which
						lies just below the intersecting vertex.   The articulation before that is
						the one that is the one that is sending the x value straight into the
						intersecting vertex.  Delete that point as well so that the entire edge is
						shifted to the outside of the intersecting vertex.  This will get repeated
						for each vertex that is intersecting.
					*/
					Point2D previousArticulation = articulations.get(articulations.size() - 2);
					int closenessHeight = 50;
					double previousY = previousArticulation.getY();
					if (vertexClipper.isTooCloseY(y, previousY, closenessHeight)) {
						articulations.remove(articulations.size() - 1);
						articulations.remove(articulations.size() - 1);
						Point2D newPrevious = articulations.get(articulations.size() - 1);
						y = newPrevious.getY();
					}
				}

				// p2 - move over; same y
				int offset = Math.max(vertexToEdgeOffset, distanceSpacing);
				offset *= exaggerationFactor;
				x = vertexClipper.getSideOffset(otherVertex, offset);
				articulations.add(new Point2D.Double(x, y));

				// p3 - same x; move y above/below the vertex
				y = vertexClipper.getBottomOffset(otherVertex, vertexToEdgeOffset);
				articulations.add(new Point2D.Double(x, y));

				// p4 - move over back to our original x; same y
				x = edgeX;
				articulations.add(new Point2D.Double(x, y));
			}
		}
	}

	private boolean useSimpleRouting() {
		return !getLayoutOptions().useEdgeRoutingAroundVertices();
	}

	private List<Point2D> routeLoopEdge(Vertex2d start, Vertex2d end, double x) {

		// going backwards
		List<Point2D> articulations = new ArrayList<>();

		int startRow = start.rowIndex;
		int endRow = end.rowIndex;
		if (startRow > endRow) { // going upwards			
			endRow = start.rowIndex;
			startRow = end.rowIndex;
		}

		int delta = endRow - startRow;
		x += delta; // adding the delta makes overlap less likely

		Point2D startVertexPoint = start.center;
		double y1 = startVertexPoint.getY();
		Point2D first = new Point2D.Double(x, y1);
		articulations.add(first);

		// loop second point - same y coord as destination;
		// 					   x is the col after the outermost dominated vertex

		Point2D endVertexPoint = end.center;
		double y2 = endVertexPoint.getY();
		Point2D second = new Point2D.Double(x, y2);
		articulations.add(second);

		return articulations;
	}

	private void lighten(FGEdge e) {

		if (!getLayoutOptions().useDimmedReturnEdges()) {
			return;
		}

		// assumption: edges that move to the left in this layout are return flows that happen
		//             after the code block has been executed.  We dim those a bit so that they
		//             produce less clutter.
		e.setDefaultAlpha(.25);
	}

	private FGVertex getRightmostVertex(LayoutLocationMap<FGVertex, FGEdge> layoutLocations,
			Vertex2dFactory vertex2dFactory, Set<FGVertex> vertices) {

		List<Vertex2d> points = new ArrayList<>();
		for (FGVertex v : vertices) {
			Vertex2d v2d = vertex2dFactory.get(v);
			points.add(v2d);
		}

		FGVertex v = getRightmostVertex(points);
		return v;
	}

	private FGVertex getRightmostVertex(Collection<Vertex2d> points) {

		Vertex2d rightmost = null;
		for (Vertex2d v2d : points) {
			if (rightmost == null) {
				rightmost = v2d;
			}
			else {
				// the rightmost is that which extends furthest to the right
				double current = rightmost.getRight();
				double other = v2d.getRight();
				if (other > current) {
					rightmost = v2d;
				}
			}
		}

		return rightmost.v;
	}

	@Override
	public boolean usesEdgeArticulations() {
		return true;
	}

	@Override
	protected Point2D getVertexLocation(FGVertex v, Column col, Row<FGVertex> row,
			Rectangle bounds) {
		return getCenteredVertexLocation(v, col, row, bounds);
	}

	private void debug(String text) {
		// System.err.println(text);
	}

	private void printParts(int depth, BlockGraph block) {
		int blockSize = block.getSize();

		debug(printDepth(0, depth) + PcodeBlock.typeToName(block.getType()) + "  - (" +
			block.getStart() + "->" + block.getStop() + ") ");

		for (int i = 0; i < blockSize; i++) {
			PcodeBlock child = block.getBlock(i);
			StringBuilder buffy = new StringBuilder();
			buffy.append(printDepth(1, depth + 1)).append(' ').append(child);

			debug(buffy.toString());
		}

		for (int i = 0; i < blockSize; i++) {
			PcodeBlock child = block.getBlock(i);
			if (child instanceof BlockGraph) {
				printParts(depth + 1, (BlockGraph) child);
				continue;
			}
		}
	}

	private void printConvertedStructure(int depth, DecompilerBlockGraph blockGraph) {
		String depthString = printDepth(depth, depth);

		String blockName = blockGraph.getName();
		if (blockName != null) {
			debug(depthString + blockName);

			String childrenString = blockGraph.getChildrenString(depth + 1);
			if (!childrenString.isEmpty()) {
				debug(childrenString);
			}
		}

		List<DecompilerBlock> list = blockGraph.allChildren;
		for (DecompilerBlock block : list) {
			if (block instanceof DecompilerBlockGraph) {
				printConvertedStructure(depth + 1, (DecompilerBlockGraph) block);
			}
			else {
				debug(depthString + "::" + block.getName());
			}
		}
	}

	private void printGraphStrucure(BlockGraph blockGraph) {
		printBlock(new AtomicInteger(0), 0, blockGraph);
	}

	private void printBlock(AtomicInteger parentID, int depth, BlockGraph block) {
		debug(parentID + " " + printDepth(depth, depth) + +(parentID.get() - 1) + " " +
			PcodeBlock.typeToName(block.getType()) + "  - (" + block.getStart() + "->" +
			block.getStop() + ") ");

		int blockSize = block.getSize();
		int ID = parentID.getAndIncrement();

		for (int i = 0; i < blockSize; i++) {
			PcodeBlock child = block.getBlock(i);
			if (child instanceof BlockGraph) {
				printBlock(parentID, depth + 1, (BlockGraph) child);
				continue;
			}

			BlockCopy copy = (BlockCopy) child;

			StringBuilder buffy = new StringBuilder();
			buffy.append(printDepth(depth, depth + 1))
					.append(' ')
					.append(ID)
					.append(" plain - ")
					.append(copy.getRef());

			debug(buffy.toString());
		}
	}

	private String printDepth(int level, int depth) {
		if (depth == 0) {
			return "";
		}

		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < depth * 2; i++) {
			buffy.append(' ');
		}

		buffy.append(' ');
		return buffy.toString();
	}

	private GridLocationMap<FGVertex, FGEdge> assignCoordinates(
			VisualGraph<FGVertex, FGEdge> jungGraph, DecompilerBlockGraph root) {
		GridLocationMap<FGVertex, FGEdge> gridLocations = new GridLocationMap<>();

		root.setCol(0);  // recursive
		debug("\n\n");
		root.setRows(0); // recursive

		Collection<FGVertex> vertices = jungGraph.getVertices();
		for (FGVertex vertex : vertices) {
			DecompilerBlock block = root.getBlock(vertex);
			int col = block.getCol();
			int row = block.getRow();
			gridLocations.set(vertex, row, col);
		}

		return gridLocations;
	}

	private FGVertex getVertex(VisualGraph<FGVertex, FGEdge> jungGraph, Address address) {
		Collection<FGVertex> vertices = jungGraph.getVertices();
		for (FGVertex v : vertices) {
			if (v.containsAddress(address)) {
				return v;
			}
		}

		// this is unusual; can happen if the program is being changed while this is running
		// throw new AssertException("Cannot find vertex for address: " + address);
		Msg.debug(this, "Unable to find vertex for address; has the program changed?: " + address);
		return null;
	}

	private BlockGraph buildCurrentFunctionGraph(Program program,
			VisualGraph<FGVertex, FGEdge> jungGraph, TaskMonitor taskMonitor)
			throws CancelledException {

		CodeBlockModel blockModel = new BasicBlockModel(program);
		AddressSetView addresses = function.getBody();
		CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, taskMonitor);

		BlockGraph blockGraph = new BlockGraph();
		BidiMap<CodeBlock, PcodeBlock> bidiMap = new DualHashBidiMap<>();
		for (; iterator.hasNext();) {
			taskMonitor.checkCanceled();

			CodeBlock codeBlock = iterator.next();
			FGVertex vertex = getVertex(jungGraph, codeBlock.getMinAddress());
			if (vertex == null) {
				// this is unusual; can happen if the program is being changed while this is running
				continue;
			}

			PcodeBlock pcodeBlock = new BlockCopy(vertex, codeBlock.getMinAddress());
			bidiMap.put(codeBlock, pcodeBlock);
			blockGraph.addBlock(pcodeBlock);
		}

		for (CodeBlock block : bidiMap.keySet()) {
			taskMonitor.checkCanceled();

			CodeBlockReferenceIterator destinations = block.getDestinations(taskMonitor);
			while (destinations.hasNext()) {
				taskMonitor.checkCanceled();

				CodeBlockReference ref = destinations.next();
				// We only want control flow that is internal to the function. Make sure to
				// exclude the case where a function contains a (recursive) call to itself:
				// The reference would be between addresses internal to the function, but the
				// link doesn't represent internal flow. So we filter out ANY call reference.
				if (ref.getFlowType().isCall()) {
					continue;
				}
				CodeBlock destination = ref.getDestinationBlock();

				PcodeBlock sourcePcodeBlock = bidiMap.get(block);
				PcodeBlock destPcodeBlock = bidiMap.get(destination);
				if (destPcodeBlock == null) {
					continue;
				}

				blockGraph.addEdge(sourcePcodeBlock, destPcodeBlock);
			}
		}

		blockGraph.setIndices();
		return blockGraph;
	}

	@Override
	protected AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedFGLayout(
			FunctionGraph newGraph) {
		return new DecompilerNestedLayout(newGraph, getLayoutName(), false);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Encapsulates knowledge of edge direction (up/down, left/right) and uses that knowledge
	 * to report vertex offsets from the appropriate side and top/bottom
	 */
	private class VertexClipper {

		boolean goingLeft;
		boolean goingDown;

		VertexClipper(boolean isLeft, boolean isBottom) {
			this.goingLeft = isLeft;
			this.goingDown = isBottom;
		}

		private double getSide(Vertex2d v) {
			return goingLeft ? v.getLeft() : v.getRight();
		}

		double getTopOffset(Vertex2d v, int offset) {
			return goingDown ? v.getTop() - offset : v.getBottom() + offset;
		}

		double getBottomOffset(Vertex2d v, int offset) {
			return goingDown ? v.getBottom() + offset : v.getTop() - offset;
		}

		double getSideOffset(Vertex2d v, int offset) {

			double side = getSide(v);
			if (goingLeft) {
				return side - offset;
			}
			return side + offset;
		}

		boolean isTooCloseY(double topY, double bottomY, double threshold) {
			double delta = goingDown ? topY - bottomY : bottomY - topY;
			return delta < threshold;
		}

		boolean isClippingX(Vertex2d v, double x) {

			double side = getSide(v);
			if (goingLeft) {
				return x >= side;
			}
			return x < side;
		}
	}

	/**
	 * Factory for creating and caching {@link Vertex2d} objects
	 */
	private class Vertex2dFactory {

		private VisualGraphVertexShapeTransformer<FGVertex> vertexShaper;
		private Map<FGVertex, Point2D> vertexLayoutLocations;
		private LayoutLocationMap<FGVertex, FGEdge> layoutToGridMap;
		private int edgeOffset;
		private Map<FGVertex, Vertex2d> cache =
			LazyMap.lazyMap(new HashMap<>(), v -> new Vertex2d(v, vertexShaper,
				vertexLayoutLocations, layoutToGridMap, getEdgeOffset()));

		Vertex2dFactory(VisualGraphVertexShapeTransformer<FGVertex> transformer,
				Map<FGVertex, Point2D> vertexLayoutLocations,
				LayoutLocationMap<FGVertex, FGEdge> layoutToGridMap, int edgeOffset) {
			this.vertexShaper = transformer;
			this.vertexLayoutLocations = vertexLayoutLocations;
			this.layoutToGridMap = layoutToGridMap;
			this.edgeOffset = edgeOffset;
		}

		Column getColumn(double x) {
			return layoutToGridMap.getColumnContaining((int) x);
		}

		private int getEdgeOffset() {
			return edgeOffset;
		}

		Vertex2d get(FGVertex v) {
			return cache.get(v);
		}

		Vertex2d get(int rowIndex, int columnIndex) {

			Row<FGVertex> row = layoutToGridMap.row(rowIndex);
			FGVertex v = row.getVertex(columnIndex);
			if (v == null) {
				return null;
			}
			return get(v);
		}

		void dispose() {
			cache.clear();
		}
	}

	/**
	 * A class that represents 2D information about the contained vertex, such as location,
	 * bounds, row and column of the layout grid.
	 */
	private class Vertex2d {

		private FGVertex v;
		private Row<FGVertex> row;
		private Column column;
		private int rowIndex;
		private int columnIndex;
		private Point2D center; // center point of vertex shape
		private Shape shape;
		private Rectangle bounds; // centered over the 'location'
		private int edgeOffset;

		Vertex2d(FGVertex v, VisualGraphVertexShapeTransformer<FGVertex> transformer,
				Map<FGVertex, Point2D> vertexLayoutLocations,
				LayoutLocationMap<FGVertex, FGEdge> layoutLocations, int edgeOffset) {

			this.v = v;
			this.row = layoutLocations.row(v);
			this.rowIndex = row.index;
			this.column = layoutLocations.col(v);
			this.columnIndex = column.index;
			this.center = vertexLayoutLocations.get(v);
			this.shape = transformer.apply(v);
			this.bounds = shape.getBounds();
			this.edgeOffset = edgeOffset;

			// center bounds over location (this is how the graph gets painted)
			double cornerX = center.getX() + bounds.getWidth() / 2;
			double cornerY = center.getY() + bounds.getHeight() / 2;
			Point2D corner = new Point2D.Double(cornerX, cornerY);
			bounds.setFrameFromCenter(center, corner);
		}

		double getY() {
			return center.getY();
		}

		double getX() {
			return center.getX();
		}

		double getLeft() {
			return center.getX() - (bounds.width >> 1);
		}

		double getRight() {
			return center.getX() + (bounds.width >> 1);
		}

		double getBottom() {
			return center.getY() + (bounds.height >> 1);
		}

		double getTop() {
			return center.getY() - (bounds.height >> 1);
		}

		int getEdgeOffset() {
			return edgeOffset;
		}

		@Override
		public String toString() {
			return v.toString();
		}
	}

	private class DecompilerBlockGraph extends DecompilerBlock {

		protected List<DecompilerBlock> allChildren = new ArrayList<>();

		DecompilerBlockGraph(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);

			int childCount = blockGraph.getSize();
			for (int i = 0; i < childCount; i++) {
				PcodeBlock block = blockGraph.getBlock(i);
				if (block instanceof BlockGraph) {
					DecompilerBlockGraph decompilerBlock =
						getDecompilerBlock(this, (BlockGraph) block);
					allChildren.add(decompilerBlock);
				}

				if (block instanceof BlockCopy) {
					DecompilerCopy decompilerCopy = new DecompilerCopy(this, (BlockCopy) block);
					allChildren.add(decompilerCopy);
				}
			}
		}

		@Override
		DecompilerBlock getBlock(FGVertex vertex) {
			for (DecompilerBlock child : allChildren) {
				DecompilerBlock block = child.getBlock(vertex);
				if (block != null) {
					return block;
				}
			}

			return null;
		}

		@Override
		DecompilerBlock getParentLoop() {
			if (parent == null) {
				return null;
			}
			return parent.getParentLoop();
		}

		@Override
		Set<FGVertex> getVertices() {
			Set<FGVertex> set = new HashSet<>();
			for (DecompilerBlock child : allChildren) {
				set.addAll(child.getVertices());
			}
			return set;
		}

		@Override
		void setCol(int col) {

			//
			// The *default* structure for children's nesting:
			// -the first node is always at the root nesting level
			// -all other children are indented by 1
			//
			for (int i = 0; i < allChildren.size(); i++) {
				int column = (i == 0) ? col : col + 1;
				DecompilerBlock block = allChildren.get(i);
				block.setCol(column);
			}

			doSetCol(col);
		}

		protected void doSetCol(int col) {
			super.setCol(col);
		}

		int setRows(int startRow) {

			int row = startRow;

			for (DecompilerBlock block : allChildren) {
				if (block instanceof DecompilerBlockGraph) {
					row = ((DecompilerBlockGraph) block).setRows(row);
				}
				else {
					block.setRow(row++);
				}
			}

			return row;
		}

		@Override
		String getName() {
			return null;
		}

		@Override
		String getChildrenString(int depth) {
			StringBuilder buffy = new StringBuilder();
			int childCount = 0;
			for (DecompilerBlock block : allChildren) {
				if (block instanceof DecompilerBlockGraph) {

					String blockName = block.getName();
					if (blockName != null) {
						childCount++;

						if (childCount > 1) {
							buffy.append('\n');
						}
						buffy.append(printDepth(depth, depth));
//						buffy.append(childCount).append(' ');
						buffy.append(' ');
						buffy.append(blockName);
					}

				}
			}

			return buffy.toString();
		}
	}

	private abstract class DecompilerBlock {
		protected DecompilerBlock parent;
		protected PcodeBlock pcodeBlock;
		private int row;
		private int col;

		DecompilerBlock(DecompilerBlock parent, PcodeBlock pcodeBlock) {
			this.parent = parent;
			this.pcodeBlock = pcodeBlock;
		}

		void setRow(int row) {
			this.row = row;
		}

		void setCol(int col) {
			this.col = col;
		}

		int getRow() {
			return row;
		}

		int getCol() {
			return col;
		}

		abstract DecompilerBlock getBlock(FGVertex vertex);

		abstract Set<FGVertex> getVertices();

		abstract DecompilerBlock getParentLoop();

		abstract String getName();

		abstract String getChildrenString(int depth);

		@Override
		public String toString() {
			return PcodeBlock.typeToName(pcodeBlock.getType()) + " - " + getName() + " - " +
				pcodeBlock.getStart();
		}
	}

	private class DecompilerCopy extends DecompilerBlock {
		private BlockCopy copy;
		private Set<FGVertex> vertexSet = new HashSet<>();

		DecompilerCopy(DecompilerBlockGraph parent, BlockCopy copy) {
			super(parent, copy);
			this.copy = copy;
			vertexSet.add((FGVertex) copy.getRef());
			vertexSet = Collections.unmodifiableSet(vertexSet);
		}

		FGVertex getVertex() {
			return (FGVertex) copy.getRef();
		}

		@Override
		DecompilerBlock getBlock(FGVertex vertex) {
			//
			// Note: we currently allow grouping in this layout.  When we search for a vertex,
			//       we have to check each vertex inside of the given group *and* each vertex
			//       inside of the vertex that belongs to this decompiler block.
			//
			if (vertex instanceof GroupedFunctionGraphVertex) {
				Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) vertex).getVertices();
				for (FGVertex collapsedVertex : vertices) {
					// note: the group may itself contain other groups--it's recursive
					DecompilerBlock block = getBlock(collapsedVertex);
					if (block != null) {
						return block;
					}
				}
			}

			FGVertex myVertex = getVertex();
			DecompilerBlock block = compareToMyVertex(myVertex, vertex);
			return block;
		}

		private DecompilerBlock compareToMyVertex(FGVertex myVertex, FGVertex vertex) {
			if (myVertex instanceof GroupedFunctionGraphVertex) {
				Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) myVertex).getVertices();
				for (FGVertex myCollapsedVertex : vertices) {
					DecompilerBlock block = compareToMyVertex(myCollapsedVertex, vertex);
					if (block != null) {
						return block;
					}
				}
			}

			if (myVertex.equals(vertex)) {
				return this;
			}
			return null;
		}

		@Override
		DecompilerBlock getParentLoop() {
			return parent.getParentLoop();
		}

		@Override
		Set<FGVertex> getVertices() {
			return vertexSet;
		}

		@Override
		String getName() {
			return "Copy"; // we don't usually want to see this
		}

		@Override
		String getChildrenString(int depth) {
			return null;
		}
	}

	private DecompilerBlockGraph getDecompilerBlock(DecompilerBlockGraph parent, BlockGraph block) {

		switch (block.getType()) {
			case PLAIN:
				return new DecompilerBlockGraph(parent, block);
			case BASIC:
				return new DecompilerBlockGraph(parent, block);
			case GRAPH:
				return new DecompilerBlockGraph(parent, block);
			case COPY:
				return new PlainBlock(parent, block);
			case GOTO:
				return new DecompilerBlockGraph(parent, block);
			case MULTIGOTO:
				return new DecompilerBlockGraph(parent, block);
			case LIST:
				return new ListBlock(parent, block);
			case CONDITION:
				return new ConditionBlock(parent, block); //  not sure
			case PROPERIF:
				return new IfBlock(parent, block);
			case IFELSE:
				return new IfElseBlock(parent, block);
			case IFGOTO:
				return new IfBlock(parent, block); //  not sure
			case WHILEDO:
				return new WhileLoopBlock(parent, block);
			case DOWHILE:
				return new DoLoopBlock(parent, block);
			case SWITCH:
				return new SwitchBlock(parent, block);
			case INFLOOP:
				return new DecompilerBlockGraph(parent, block);
		}

		throw new AssertException(
			"Unhandled Decompiler Type: " + PcodeBlock.typeToName(block.getType()));
	}

	private abstract class DecompilerLoop extends DecompilerBlockGraph {

		DecompilerLoop(DecompilerBlockGraph parent, BlockGraph block) {
			super(parent, block);
		}

		@Override
		DecompilerBlock getParentLoop() {
			return this;
		}
	}

	private class PlainBlock extends DecompilerBlockGraph {
		PlainBlock(DecompilerBlockGraph parent, BlockGraph block) {
			super(parent, block);
		}

		@Override
		String getName() {
			return "Plain";
		}
	}

	private class ListBlock extends DecompilerBlockGraph {
		ListBlock(DecompilerBlockGraph parent, BlockGraph block) {
			super(parent, block);
		}

		@Override
		void setCol(int col) {

			//
			// The 'list' structure for children's nesting:
			// -all nodes are at the same level
			//
			for (DecompilerBlock block : allChildren) {
				int column = col;
				block.setCol(column);
			}

			doSetCol(col);
		}

		@Override
		String getName() {
			return parent.getName();
		}
	}

	private class ConditionBlock extends DecompilerBlockGraph {

		ConditionBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		void setCol(int col) {

			//
			// The 'condition' structure for children's nesting:
			// -the first condition is at the base index
			// -each successive condition is another level nested
			//
			int column = col;
			for (DecompilerBlock block : allChildren) {
				block.setCol(column);
				column++;
			}

			doSetCol(col);
		}

		@Override
		String getName() {
			return "Condition";
		}
	}

	private class WhileLoopBlock extends DecompilerLoop {

		WhileLoopBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "While Loop";
		}
	}

	private class DoLoopBlock extends DecompilerLoop {

		DoLoopBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		void setCol(int col) {

			//
			// The 'do' structure for children's nesting:
			// -all blocks nested
			//
			int column = col + 1;
			for (DecompilerBlock block : allChildren) {
				block.setCol(column);
			}

			doSetCol(col);
		}

		@Override
		String getName() {
			return "Do Loop";
		}
	}

	private class IfBlock extends DecompilerBlockGraph {

		IfBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "If";
		}
	}

	private class IfElseBlock extends DecompilerBlockGraph {

		IfElseBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "If / Else";
		}
	}

	private class SwitchBlock extends DecompilerBlockGraph {

		SwitchBlock(DecompilerBlockGraph parent, BlockGraph blockGraph) {
			super(parent, blockGraph);
		}

		@Override
		String getName() {
			return "Switch";
		}
	}

}
