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
package ghidra.graph.viewer.layout;

import java.awt.*;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.AbstractLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A base layout that marries the Visual Graph and Jung layout interfaces.   This class allows
 * you to create new layouts while stubbing the Jung layout methods.
 *
 * <P>This class essentially takes in client-produced grid row and column indices and
 * produces layout locations for those values.
 *
 * <P>This an implementation the Jung {@link Layout} interface that handles most of the
 * layout implementation for you.  Things to know:
 * <UL>
 * 	<LI>You should call initialize() inside of your constructor</LI>
 *  <LI>You must implement {@link #performInitialGridLayout(VisualGraph)} - this is where
 *      you align your vertices (and optionally edge articulations) on a grid.  This grid
 *      will be translated into layout space points for you.</LI>
 *  <LI>If you wish to use articulation points in your edges, you must override
 *      {@link #usesEdgeArticulations()} to return true.</LI>
 * </UL>
 *
 * <p><a id="column_centering"></A>By default, this class will create x-position values that
 * are aligned with the column's x-position.   You can override
 * {@link #getVertexLocation(VisualVertex, Column, Row, Rectangle)} in order to center the
 * vertex within its column
 * {@link #getCenteredVertexLocation(VisualVertex, Column, Row, Rectangle)}.  Also note though
 * that if your layout returns true for {@link #isCondensedLayout()},
 * then the centering will be condensed and slightly off.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 *
 * @see GridLocationMap
 * @see LayoutPositions
 */
//@formatter:off
public abstract class AbstractVisualGraphLayout<V extends VisualVertex,
	                                            E extends VisualEdge<V>>
	extends AbstractLayout<V, E>
	implements VisualGraphLayout<V, E> {
//@formatter:on

	private WeakSet<LayoutListener<V, E>> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	private ArticulatedEdgeTransformer<V, E> edgeShapeTransformer =
		new ArticulatedEdgeTransformer<>();
	private ArticulatedEdgeRenderer<V, E> edgeRenderer = new ArticulatedEdgeRenderer<>();

	protected String layoutName;
	protected boolean layoutInitialized;

	protected TaskMonitor monitor = TaskMonitor.DUMMY;

	protected AbstractVisualGraphLayout(Graph<V, E> graph, String layoutName) {
		super(graph);
		this.layoutName = layoutName;
	}

	/**
	 * Returns the name of this layout
	 * @return the name of this layout
	 */
	public String getLayoutName() {
		return layoutName;
	}

	/**
	 * This is the method that is called to perform the actual layout.  While this method is
	 * running, the {@link #monitor} variable has been set so that you can call
	 * {@link TaskMonitor#checkCanceled()}.
	 *
	 * @param g the graph
	 * @return the new grid location
	 * @throws CancelledException if the operation was cancelled
	 */
	protected abstract GridLocationMap<V, E> performInitialGridLayout(VisualGraph<V, E> g)
			throws CancelledException;

	public void setTaskMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
	}

	@Override
	public BasicEdgeRenderer<V, E> getEdgeRenderer() {
		return edgeRenderer;
	}

	@Override
	public Function<E, Shape> getEdgeShapeTransformer() {
		return edgeShapeTransformer;
	}

	@Override
	public EdgeLabel<V, E> getEdgeLabelRenderer() {
		return null;
	}

	@Override
	public boolean usesEdgeArticulations() {
		return false;
	}

	@Override
	public void reset() {
		// stub (usually a relayout)
	}

	@Override
	public void dispose() {
		listeners.clear();
	}

	/**
	 * Returns true if this layout is in a condensed mode, which means to reduce space
	 * between vertices and edges.  This is useful to save space.  Subclasses may choose to
	 * have this setting controlled via an option that the user can toggle.
	 *
	 * @return true for a condensed layout
	 */
	protected boolean isCondensedLayout() {
		return false;
	}

	/*
	 * Note: this is called trigger the layout to take place.   This will be called repeatedly
	 * by the Jung layout we extends, which is why we cache the results here.   Subclasses
	 * are expected to call initialize at construction time.
	 */
	@Override
	public void initialize() {
		if (layoutInitialized) {
			return;
		}

		int vertexCount = graph.getVertexCount();
		if (vertexCount == 0) {
			return;
		}

		layoutInitialized = true;

		LayoutPositions<V, E> positions = calculateLocations(getVisualGraph(), monitor);
		applyNewLocations(positions.getVertexLocations());
		applyNewArticulations(positions.getEdgeArticulations());
		positions.dispose();
	}

	@Override
	public LayoutPositions<V, E> calculateLocations(VisualGraph<V, E> visualGraph,
			TaskMonitor taskMonitor) {
		int vertexCount = visualGraph.getVertexCount();
		if (vertexCount == 0) {
			return LayoutPositions.createEmptyPositions();
		}

		return doCalculateLocations(visualGraph, taskMonitor);
	}

	protected LayoutPositions<V, E> doCalculateLocations(VisualGraph<V, E> g,
			TaskMonitor taskMonitor) {

		GridLocationMap<V, E> gridLocations = null;
		try {
			monitor = taskMonitor;
			gridLocations = performInitialGridLayout(g);
			LayoutPositions<V, E> positions = positionInLayoutSpaceFromGrid(g, gridLocations);
			return positions;
		}
		catch (CancelledException ce) {
			return LayoutPositions.createEmptyPositions();
		}
		finally {
			if (gridLocations != null) {
				gridLocations.dispose();
			}
			monitor = TaskMonitor.DUMMY;
		}
	}

	/**
	 * This class has implemented {@link #cloneLayout(VisualGraph)} in order to properly
	 * initialize location information in the layout so that subclasses do not have to.  Each
	 * subclass still needs to create the new instance of the layout that is being cloned, as
	 * this class does not know how to do so.
	 *
	 * @param newGraph the new graph for the new layout
	 * @return the new layout
	 */
	public abstract AbstractVisualGraphLayout<V, E> createClonedLayout(VisualGraph<V, E> newGraph);

	@Override
	public VisualGraphLayout<V, E> cloneLayout(VisualGraph<V, E> newGraph) {
		AbstractVisualGraphLayout<V, E> layout = createClonedLayout(newGraph);
		initializeClonedLayout(layout);
		return layout;
	}

	/**
	 * Takes the given layout and copies the layout information this layout into that layout
	 *
	 * @param newLayout the new layout to update
	 */
	protected void initializeClonedLayout(AbstractVisualGraphLayout<V, E> newLayout) {

		AbstractVisualGraphLayout<V, E> originalLayout = this;
		VisualGraph<V, E> originalGraph = getVisualGraph();
		Collection<V> vertices = originalGraph.getVertices();
		for (V v : vertices) {
			Point2D location = originalLayout.apply(v);
			newLayout.setLocation(v, location);
		}

		Collection<E> edges = originalGraph.getEdges();
		Map<E, List<Point2D>> edgesToBends =
			edges.stream().collect(Collectors.toMap(e -> e, e -> e.getArticulationPoints()));

		VisualGraph<V, E> newGraph = newLayout.getVisualGraph();
		Collection<E> newEdges = newGraph.getEdges();
		for (E e : newEdges) {

			List<Point2D> bends = edgesToBends.get(e);
			if (bends == null) {
				// New edge is not in the old graph.  This can happen if the old graph has
				// grouped vertices and some edges have been removed.
				continue;
			}

			// clone the points too so the graphs don't step on each other
			List<Point2D> newBends = new ArrayList<>();
			for (Point2D p : bends) {
				newBends.add((Point2D) p.clone());
			}

			e.setArticulationPoints(newBends);
		}

		newLayout.layoutInitialized = true;
	}

	protected void applyNewLocations(Map<V, Point2D> newLocations) {
		Set<Entry<V, Point2D>> entrySet = newLocations.entrySet();
		for (Entry<V, Point2D> entry : entrySet) {
			V vertex = entry.getKey();
			Point2D location = entry.getValue();
			setLocation(vertex, location);
			vertex.setLocation(location);
		}
	}

	// note: some layouts do not use articulations
	protected void applyNewArticulations(Map<E, List<Point2D>> edgeArticulations) {
		Set<Entry<E, List<Point2D>>> entrySet = edgeArticulations.entrySet();
		for (Entry<E, List<Point2D>> entry : entrySet) {
			E edge = entry.getKey();
			List<Point2D> articulations = entry.getValue();
			edge.setArticulationPoints(articulations);
		}
	}

	protected LayoutPositions<V, E> positionInLayoutSpaceFromGrid(VisualGraph<V, E> visualGraph,
			GridLocationMap<V, E> gridLocations) throws CancelledException {

		VisualGraphVertexShapeTransformer<V> transformer =
			new VisualGraphVertexShapeTransformer<>();
		Collection<V> vertices = visualGraph.getVertices();
		Collection<E> edges = visualGraph.getEdges();

		boolean isCondensed = isCondensedLayout();

		LayoutLocationMap<V, E> layoutLocations =
			new LayoutLocationMap<>(gridLocations, transformer, isCondensed, monitor);

		Map<V, Point2D> vertexLayoutLocations =
			positionVerticesInLayoutSpace(transformer, vertices, layoutLocations);

		Rectangle graphBounds = getTotalGraphSize(vertexLayoutLocations, transformer);
		double centerX = graphBounds.getCenterX();
		double centerY = graphBounds.getCenterY();

		//
		// Condense vertices before placing edges.  This allows layouts to perform custom routing
		// of edges around vertices *after* condensing.
		//
		if (isCondensed) {
			List<Row<V>> rows = gridLocations.rows();
			condenseVertices(rows, vertexLayoutLocations, transformer, centerX, centerY);
		}

		Map<E, List<Point2D>> edgeLayoutArticulations = positionEdgeArticulationsInLayoutSpace(
			transformer, vertexLayoutLocations, edges, layoutLocations);

		if (isCondensed) {
			// note: some layouts will not condense the edges, as they perform custom routing
			List<Row<V>> rows = gridLocations.rows();
			condenseEdges(rows, edgeLayoutArticulations, centerX, centerY);
		}

		// DEGUG triggers grid lines to be printed; useful for debugging
		// VisualGraphRenderer.DEBUG_ROW_COL_MAP.put(this, layoutLocations.copy());

		layoutLocations.dispose();
		gridLocations.dispose();

		return LayoutPositions.createNewPositions(vertexLayoutLocations, edgeLayoutArticulations);
	}

	private Map<V, Point2D> positionVerticesInLayoutSpace(
			VisualGraphVertexShapeTransformer<V> transformer, Collection<V> vertices,
			LayoutLocationMap<V, E> layoutLocations) throws CancelledException {
		// use the calculated row and column sizes to place the vertices in
		// their final positions (including x and y from bounds 'cause they're
		// centered)
		Map<V, Point2D> newLocations = new HashMap<>();
		for (V vertex : vertices) {
			monitor.checkCanceled();

			Row<V> row = layoutLocations.row(vertex);
			Column column = layoutLocations.col(vertex);

			Shape shape = transformer.apply(vertex);
			Rectangle bounds = shape.getBounds();
			Point2D location = getVertexLocation(vertex, column, row, bounds);
			newLocations.put(vertex, location);
		}
		return newLocations;
	}

	protected Point2D getVertexLocation(V v, Column col, Row<V> row, Rectangle bounds) {
		int x = col.x - bounds.x;
		int y = row.y - bounds.y;
		return new Point2D.Double(x, y);
	}

	/**
	 * Returns a location for the given vertex that is centered within its cell
	 *
	 * @param v the vertex
	 * @param col the vertex's column in the grid
	 * @param row the vertex's row in the grid
	 * @param bounds the bounds of the vertex in the layout space
	 * @return the centered location
	 */
	protected Point2D getCenteredVertexLocation(V v, Column col, Row<V> row, Rectangle bounds) {
		//
		// Move x over to compensate for vertex painting.   Edges are drawn from the center of the
		// vertex.  Thus, if you have vertices with two different widths, then the edge between
		// them will not be straight *when the vertices are painted off-center on their column*
		// (which means they are left-aligned).  By centering the vertex, the center points of
		// the differently sized vertices (on the same column and different rows) will be aligned.
		//
		boolean isCondensed = isCondensedLayout();
		int x = col.x + (col.getPaddedWidth(isCondensed) >> 1);
		if (isCondensed) {
			x = col.x;
		}

		int y = row.y + (bounds.height >> 1);
		return new Point2D.Double(x, y);
	}

	protected Map<E, List<Point2D>> positionEdgeArticulationsInLayoutSpace(
			VisualGraphVertexShapeTransformer<V> transformer, Map<V, Point2D> vertexLayoutLocations,
			Collection<E> edges, LayoutLocationMap<V, E> layoutLocations)
			throws CancelledException {

		Map<E, List<Point2D>> newEdgeArticulations = new HashMap<>();
		for (E edge : edges) {
			monitor.checkCanceled();

			List<Point2D> newArticulations = new ArrayList<>();
			for (Point gridPoint : layoutLocations.articulations(edge)) {
				Row<V> row = layoutLocations.row(gridPoint.y);
				Column column = layoutLocations.col(gridPoint.x);

				Point2D location = getEdgeLocation(column, row);
				newArticulations.add(location);
			}
			newEdgeArticulations.put(edge, newArticulations);
		}
		return newEdgeArticulations;
	}

	protected Point2D getEdgeLocation(Column col, Row<V> row) {
		return new Point2D.Double(col.x, row.y);
	}

	protected Point2D getCenteredEdgeLocation(Column col, Row<V> row) {
		//
		// half-height offsets the articulation points, which keeps long edge lines from
		// overlapping as much
		//
		boolean isCondensed = isCondensedLayout();
		int x = col.x + (col.getPaddedWidth(isCondensed) >> 1);
		int y = row.y + (row.getPaddedHeight(isCondensed) >> 1);
		return new Point2D.Double(x, y);
	}

	private Rectangle getTotalGraphSize(Map<V, Point2D> vertexLocationMap,
			com.google.common.base.Function<V, Shape> vertexShapeTransformer) {

		// note: do not include edges in the size of the graph at this point, as some layouts use
		//       custom edge routing after this method is called
		Set<V> vertices = vertexLocationMap.keySet();
		Set<E> edges = Collections.emptySet();

		Function<V, Rectangle> vertexToBounds = v -> {

			Shape s = vertexShapeTransformer.apply(v);
			Rectangle bounds = s.getBounds();
			Point2D p = vertexLocationMap.get(v);
			bounds.setLocation(new Point((int) p.getX(), (int) p.getY()));
			return bounds;
		};

		if (!usesEdgeArticulations()) {

			Rectangle bounds =
				GraphViewerUtils.getBoundsForVerticesInLayoutSpace(vertices, vertexToBounds);
			return bounds;
		}

		Function<E, List<Point2D>> edgeToArticulations = e -> Collections.emptyList();
		Rectangle bounds = GraphViewerUtils.getTotalGraphSizeInLayoutSpace(vertices, edges,
			vertexToBounds, edgeToArticulations);
		return bounds;
	}

	protected void condenseVertices(List<Row<V>> rows, Map<V, Point2D> newLocations,
			VisualGraphVertexShapeTransformer<V> transformer, double centerX, double centerY) {

		//
		// Note: we move the articulations and vertices closer together on the x-axis.  We do
		//       not move the y-axis, as that is already as close together as we would like at
		//       this point.
		//
		double condenseFactor = getCondenseFactor();
		Collection<Point2D> vertexPoints = newLocations.values();
		for (Point2D point : vertexPoints) {
			double currentX = point.getX();
			double currentY = point.getY();

			// move closer to the center
			double deltaX = centerX - currentX;
			double offsetX = (deltaX * condenseFactor) + currentX;

			point.setLocation(offsetX, currentY);
		}

		//
		// The above aggressive condensing may lead to neighboring node overlapping for
		// nodes in the same row.  Check to see if we need to move the nodes to avoid this case.
		//
		unclip(rows, newLocations, transformer);
	}

	protected void condenseEdges(List<Row<V>> rows, Map<E, List<Point2D>> newEdgeArticulations,
			double centerX, double centerY) {

		//
		// Note: we move the articulations and vertices closer together on the x-axis.  We do
		//       not move the y-axis, as that is already as close together as we would like at
		//       this point.
		//
		double condenseFactor = getCondenseFactor();
		Collection<List<Point2D>> edgeArticulations = newEdgeArticulations.values();
		for (List<Point2D> edgePoints : edgeArticulations) {
			for (Point2D point : edgePoints) {
				double currentX = point.getX();
				double currentY = point.getY();

				// move closer to the center
				double deltaX = centerX - currentX;
				double offsetX = (deltaX * condenseFactor) + currentX;

				point.setLocation(offsetX, currentY);
			}
		}
	}

	/**
	 * The amount (from 0 to 1.0) by which to condense the vertices of the graph when that
	 * feature is enabled.  The default is .5 (50%).  A value of 1.0 would be fully-condensed
	 * such that all vertices are aligned on the x-axis on the center of the graph.
	 * @return the condense factor
	 */
	protected double getCondenseFactor() {
		return .5; // 50% 
	}

	private void unclip(List<Row<V>> rows, Map<V, Point2D> newLocations,
			VisualGraphVertexShapeTransformer<V> transformer) {

		for (Row<V> row : rows) {
			Integer columnCount = row.getColumnCount();
			int moveLeftStartIndex = columnCount >> 1; // start in the middle
			int moveRightStartIndex = Math.min(moveLeftStartIndex + 1, columnCount - 1);

			moveLeft(row, moveLeftStartIndex, newLocations, transformer);
			moveRight(row, moveRightStartIndex, newLocations, transformer);
		}
	}

	private void moveLeft(Row<V> row, int moveLeftStartIndex, Map<V, Point2D> vertexLocations,
			VisualGraphVertexShapeTransformer<V> transformer) {

		for (int i = moveLeftStartIndex; i >= row.getStartColumn(); i--) {
			V vertex = row.getVertex(i);
			V rightVertex = getRightVertex(row, i);
			moveLeftIfOverlaps(vertexLocations, transformer, vertex, rightVertex);
		}
	}

	private void moveRight(Row<V> row, int moveRightStartIndex, Map<V, Point2D> vertexLocations,
			VisualGraphVertexShapeTransformer<V> transformer) {

		for (int i = moveRightStartIndex; i <= row.getEndColumn(); i++) {
			V vertex = row.getVertex(i);
			V leftVertex = getLeftVertex(row, i);
			moveRightIfOverlaps(vertexLocations, transformer, vertex, leftVertex);
		}
	}

	private V getLeftVertex(Row<V> row, int index) {
		if (index == 0) {
			return null; // already leftmost
		}

		V vertex = row.getVertex(index - 1);
		if (vertex == null) {
			return getLeftVertex(row, index - 1); // get the next leftmost vertex
		}
		return vertex;
	}

	private V getRightVertex(Row<V> row, int index) {
		if (index == row.getColumnCount() - 1) {
			return null; // already rightmost
		}

		V vertex = row.getVertex(index + 1);
		if (vertex == null) {
			return getRightVertex(row, index + 1);
		}
		return vertex;
	}

	private void moveLeftIfOverlaps(Map<V, Point2D> vertexLocations,
			VisualGraphVertexShapeTransformer<V> xform, V vertex, V rightVertex) {

		moveIfOverlaps(vertexLocations, xform, vertex, rightVertex, false);
	}

	private void moveRightIfOverlaps(Map<V, Point2D> vertexLocations,
			VisualGraphVertexShapeTransformer<V> xform, V vertex, V leftVertex) {

		moveIfOverlaps(vertexLocations, xform, vertex, leftVertex, true);
	}

	private void moveIfOverlaps(Map<V, Point2D> vertexLocations,
			VisualGraphVertexShapeTransformer<V> xform, V vertex, V otherVertex,
			boolean moveRight) {

		if (vertex == null || otherVertex == null) {
			// no way to overlap
			return;
		}

		Shape vertexShape = xform.apply(vertex);
		Point2D vertexPoint = vertexLocations.get(vertex);
		Rectangle vertexBounds = vertexShape.getBounds();

		Shape otherVertexShape = xform.apply(otherVertex);
		Point2D otherVertexPoint = vertexLocations.get(otherVertex);
		Rectangle otherVertexBounds = otherVertexShape.getBounds();

		//
		// Visual points (after the centering has taken place).  Update the location to account
		// for this centering before checking for clipping.
		//
		int myWidth = vertexBounds.width >> 1; // half width
		int myHeight = vertexBounds.height >> 1; // half height
		double x = vertexPoint.getX();
		double y = vertexPoint.getY();

		int otherWidth = otherVertexBounds.width >> 1;
		int otherHeight = otherVertexBounds.height >> 1;
		double otherX = otherVertexPoint.getX();
		double otherY = otherVertexPoint.getY();

		Point myNewPoint = new Point((int) x - myWidth, (int) y - myHeight);
		vertexBounds.setLocation(myNewPoint);

		Point otherNewPoint = new Point((int) otherX - otherWidth, (int) otherY - otherHeight);
		otherVertexBounds.setLocation(otherNewPoint);

		boolean hasCrossed = hasCrossed(moveRight, myNewPoint, otherNewPoint);
		Rectangle intersection = vertexBounds.intersection(otherVertexBounds);
		if (!hasCrossed && intersection.isEmpty()) {
			return;
		}

		int spacer = 10;
		int width = myWidth + otherWidth; // the total width is half of the width from each vertex
		double offset = width + spacer;
		if (!moveRight) {
			offset = -offset;
		}

		double oldY = vertexPoint.getY();
		double newX = otherX + offset;
		vertexPoint.setLocation(newX, oldY); // editing this point changes the map's value

// DEBUG this can be deleted in the future, future, future
//		//@formatter:off
//		Msg.debug(this,
//			vertex +
//			"\n\tat " + vertexPoint.getX() +
//			"\n\tvisual x: " + myNewPoint +
//			"\n\tw: " + vertexBounds.width +
//				"\n\t\t" + otherVertex +
//				"\n\t\tat: " + otherVertexPoint +
//				"\n\t\tvisual x: " + otherNewPoint.getX() +
//			"\n\t\tw: " + otherVertexBounds.width +
//			"\n\tclip: " + intersection.width +
//			"\n\toffset: " + offset +
//			"\n\tnew pt: " + newX);
//		//@formatter:on

	}

	private boolean hasCrossed(boolean moveRight, Point p1, Point p2) {
		// The neighbors do not touch, but sometimes this is because our 'vertex' has been
		// moved to far past the 'otherVertex'.  So, we also have to check the x values.

		boolean crossed = moveRight ? p1.x < p2.x : p1.x > p2.x;
		return crossed;
	}
//==================================================================================================
// Listener Stuff
//==================================================================================================

	@Override
	public void addLayoutListener(LayoutListener<V, E> listener) {
		listeners.add(listener);
	}

	@Override
	public void removeLayoutListener(LayoutListener<V, E> listener) {

		Iterator<LayoutListener<V, E>> iterator = listeners.iterator();
		for (; iterator.hasNext();) {
			LayoutListener<V, E> layoutListener = iterator.next();
			if (layoutListener == listener) {
				iterator.remove();
			}
		}
	}

	private void fireVertexLocationChanged(V v, Point2D p) {
		fireVertexLocationChanged(v, p, ChangeType.USER);
	}

	private void fireVertexLocationChanged(V v, Point2D p, ChangeType type) {
		Iterator<LayoutListener<V, E>> iterator = listeners.iterator();
		for (; iterator.hasNext();) {
			LayoutListener<V, E> layoutListener = iterator.next();
			layoutListener.vertexLocationChanged(v, p, type);
		}
	}

	@Override
	public void setLocation(V v, Point2D location) {
		super.setLocation(v, location);
		fireVertexLocationChanged(v, location);
	}

	@Override
	public void setLocation(V v, Point2D location, ChangeType changeType) {
		super.setLocation(v, location);
		fireVertexLocationChanged(v, location, changeType);
	}

}
