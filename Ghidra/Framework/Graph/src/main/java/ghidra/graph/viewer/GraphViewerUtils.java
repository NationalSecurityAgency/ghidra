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
package ghidra.graph.viewer;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.geom.*;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.*;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.util.Pair;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.picking.PickedState;
import edu.uci.ics.jung.visualization.picking.ShapePickSupport;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.graph.viewer.shape.GraphLoopShape;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;

/**
 * This class houses various methods for translating location and size data from the various
 * graph coordinate spaces.
 * 
 * <a id="graph_spaces">Graph Spaces</a>
 * Size and location information is represented in multiple coordinate spaces, as listed below.
 * To translate from one to the other, use {@link GraphViewerUtils}; for example, to see if a 
 * mouse click is on a given vertex.
 * 
 * <ul>
 * 	<li>Layout Space - the layout contains Point2D objects that represent positions of the
 *                     vertices. 
 *  <li>Graph Space - the space where the Layout points are transformed as the view is moved 
 *                    around the screen (e.g., as the user pans)
 *  <li>View Space - the coordinate system of Java 2D rendering; scaling (zooming) transformations
 *                   are applied at this layer
 * </ul>
 * 
 * <P> Note: vertex relative means that the value is from inside the vertex, or the vertex's
 *       coordinate space (like a component that is inside the vertex), where it's 
 *       coordinate values are relative to the component's parent.
 */
public class GraphViewerUtils {

	public static final String GRAPH_DECORATOR_THREAD_POOL_NAME = "Graph Decorator";
	public static final String GRAPH_BUILDER_THREAD_POOL_NAME = "Graph Builder";

	public static final double INTERACTION_ZOOM_THRESHOLD = .2D;
	public static final double PAINT_ZOOM_THRESHOLD = .1D;

	private static final int UNSCALED_EDGE_PICK_SIZE = 10;

	private static final float EDGE_LOOP_RADIUS = 1.0f; // from 0 to 1
	private static final float BEZIER_CONTROL_POINT =
		(float) (4.0 * (StrictMath.sqrt(2.0) - 1) / 3.0) * EDGE_LOOP_RADIUS;

	// spacing for row/column cells
	public static final int EDGE_ROW_SPACING = 25;
	public static final int EDGE_COLUMN_SPACING = 25;

	// spacing around the edge of the graph
	public static final int EXTRA_LAYOUT_ROW_SPACING = 50;
	public static final int EXTRA_LAYOUT_ROW_SPACING_CONDENSED = 25;
	public static final int EXTRA_LAYOUT_COLUMN_SPACING = 50;
	public static final int EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED = 10;

	public static <V, E> Point translatePointFromViewSpaceToVertexRelativeSpace(
			VisualizationServer<V, E> viewer, Point startPoint) {
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		PickedState<V> pickedVertexState = viewer.getPickedVertexState();

		if (pickSupport == null || pickedVertexState == null) {
			return null;
		}

		Layout<V, E> layoutModel = viewer.getGraphLayout();

		double x = startPoint.getX();
		double y = startPoint.getY();
		V vertex = pickSupport.getVertex(layoutModel, x, y);
		if (vertex == null) {
			return null;
		}

		return translatePointFromViewSpaceToVertexRelativeSpace(viewer, startPoint, vertex);
	}

	public static <V, E> Point translatePointFromViewSpaceToVertexRelativeSpace(
			VisualizationServer<V, E> viewer, Point startPoint, V vertex) {

		Point graphSpaceClickPoint = translatePointFromViewSpaceToGraphSpace(startPoint, viewer);
		Point vertexUpperLeftCornerInGraphSpace =
			getVertexUpperLeftCornerInGraphSpace(viewer, vertex);

		return new Point(graphSpaceClickPoint.x - vertexUpperLeftCornerInGraphSpace.x,
			graphSpaceClickPoint.y - vertexUpperLeftCornerInGraphSpace.y);
	}

	public static <V, E> Point getVertexUpperLeftCornerInLayoutSpace(
			VisualizationServer<V, E> viewer, V vertex) {

		Point vertexGraphSpaceLocation = getVertexUpperLeftCornerInGraphSpace(viewer, vertex);
		return translatePointFromGraphSpaceToLayoutSpace(vertexGraphSpaceLocation, viewer);
	}

	public static <V, E> Point getVertexUpperLeftCornerInViewSpace(VisualizationServer<V, E> viewer,
			V vertex) {

		Point vertexGraphSpaceLocation = getVertexUpperLeftCornerInGraphSpace(viewer, vertex);
		return translatePointFromGraphSpaceToViewSpace(vertexGraphSpaceLocation, viewer);
	}

	public static <V, E> Rectangle getVertexBoundsInViewSpace(VisualizationServer<V, E> viewer,
			V vertex) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		Shape vertexGraphSpaceShape = renderContext.getVertexShapeTransformer().apply(vertex);
		Rectangle vertexBounds = vertexGraphSpaceShape.getBounds();

		// translate the location of the vertex
		Point vertexViewSpaceLocation = getVertexUpperLeftCornerInViewSpace(viewer, vertex);

		// translate the size of the rectangle
		Shape vertexViewSpaceShape = translateShapeFromGraphSpaceToViewSpace(vertexBounds, viewer);
		Rectangle vertexViewBounds = vertexViewSpaceShape.getBounds();
		vertexViewBounds.setLocation(vertexViewSpaceLocation);
		return vertexViewBounds;
	}

	public static <V, E> Rectangle getVertexBoundsInGraphSpace(VisualizationServer<V, E> viewer,
			V vertex) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		Shape vertexGraphSpaceShape = renderContext.getVertexShapeTransformer().apply(vertex);
		Rectangle vertexBounds = vertexGraphSpaceShape.getBounds();

		// translate the location of the vertex
		Point vertexGraphSpaceLocation = getVertexUpperLeftCornerInGraphSpace(viewer, vertex);
		vertexBounds.setLocation(vertexGraphSpaceLocation);
		return vertexBounds;
	}

	public static <V, E> Rectangle getVertexBoundsInLayoutSpace(VisualizationServer<V, E> viewer,
			V vertex) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		Shape vertexGraphSpaceShape = renderContext.getVertexShapeTransformer().apply(vertex);
		Rectangle vertexGraphSpaceBounds = vertexGraphSpaceShape.getBounds();

		// translate the rectangle
		Shape vertexLayoutSpaceShape =
			translateShapeFromGraphSpaceToLayoutSpace(vertexGraphSpaceBounds, viewer);
		Rectangle vertexLayoutSpaceBounds = vertexLayoutSpaceShape.getBounds();

		// translate the location of the vertex
		Point vertexLayoutSpaceLocation = getVertexUpperLeftCornerInLayoutSpace(viewer, vertex);
		vertexLayoutSpaceBounds.setLocation(vertexLayoutSpaceLocation);
		return vertexLayoutSpaceBounds;
	}

	private static <V, E> Shape translateShapeFromGraphSpaceToLayoutSpace(Shape shapeInGraphSpace,
			VisualizationServer<V, E> viewer) {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		return transformer.inverseTransform(Layer.LAYOUT, shapeInGraphSpace);
	}

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> 
		VertexMouseInfo<V, E> convertMouseEventToVertexMouseEvent(GraphViewer<V, E> viewer, 
											  					  MouseEvent mouseEvent) {
	//@formatter:on

		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (pickSupport == null) {
			return null;
		}

		Point screenClickPoint = mouseEvent.getPoint();
		Layout<V, E> layoutModel = viewer.getGraphLayout();

		double x = screenClickPoint.getX();
		double y = screenClickPoint.getY();
		V vertex = pickSupport.getVertex(layoutModel, x, y);
		if (vertex == null) {
			return null;
		}

		Point2D vertexUpperLeftRelativePoint =
			translatePointFromViewSpaceToVertexRelativeSpace(viewer, mouseEvent.getPoint());
		VertexMouseInfo<V, E> info =
			viewer.createVertexMouseInfo(mouseEvent, vertex, vertexUpperLeftRelativePoint);
		return info;
	}

	public static <V, E> Point getVertexUpperLeftCornerInGraphSpace(
			VisualizationServer<V, E> viewer, V vertex) {

		Point vertexCenterInLayoutSpace = getVertexCenterPointInLayoutSpace(viewer, vertex);
		Point vertexCenterInGraphSpace =
			translatePointFromLayoutSpaceToGraphSpace(vertexCenterInLayoutSpace, viewer);

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		Shape shape = renderContext.getVertexShapeTransformer().apply(vertex);
		Rectangle shapeBounds = shape.getBounds();
		Point vertexUpperLeftPointRelativeToVertexCenter = shapeBounds.getLocation();

		return new Point(vertexCenterInGraphSpace.x + vertexUpperLeftPointRelativeToVertexCenter.x,
			vertexCenterInGraphSpace.y + vertexUpperLeftPointRelativeToVertexCenter.y);
	}

	public static <V, E> Point translatePointFromLayoutSpaceToGraphSpace(Point2D pointInLayoutSpace,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		Point2D transformedPoint = transformer.transform(Layer.LAYOUT, pointInLayoutSpace);
		return new Point((int) transformedPoint.getX(), (int) transformedPoint.getY());
	}

	public static <V, E> Point translatePointFromLayoutSpaceToViewSpace(Point2D pointInLayoutSpace,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();

		Point2D transformedPoint = transformer.transform(pointInLayoutSpace);
		return new Point((int) transformedPoint.getX(), (int) transformedPoint.getY());
	}

	public static <V, E> Point translatePointFromViewSpaceToGraphSpace(Point2D pointInViewSpace,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();

		Point2D transformedPoint = transformer.inverseTransform(Layer.VIEW, pointInViewSpace);
		return new Point((int) transformedPoint.getX(), (int) transformedPoint.getY());
	}

	public static <V, E> Point translatePointFromViewSpaceToLayoutSpace(Point2D pointInViewSpace,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();

		Point2D transformedPoint = transformer.inverseTransform(pointInViewSpace);
		return new Point((int) transformedPoint.getX(), (int) transformedPoint.getY());
	}

	public static <V, E> Point translatePointFromGraphSpaceToViewSpace(Point2D pointInGraphSpace,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		Point2D transformedPoint = transformer.transform(Layer.VIEW, pointInGraphSpace);
		return new Point((int) transformedPoint.getX(), (int) transformedPoint.getY());
	}

	public static <V, E> Point translatePointFromGraphSpaceToLayoutSpace(Point2D pointInGraphSpace,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		Point2D transformedPoint = transformer.inverseTransform(Layer.LAYOUT, pointInGraphSpace);
		return new Point((int) transformedPoint.getX(), (int) transformedPoint.getY());
	}

	public static <V, E> Shape translateShapeFromLayoutSpaceToViewSpace(Shape shape,
			VisualizationServer<V, E> viewer) {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		return transformer.transform(shape);
	}

	public static <V, E> Shape translateShapeFromLayoutSpaceToGraphSpace(Shape shape,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		return transformer.transform(Layer.LAYOUT, shape);
	}

	public static <V, E> Shape translateShapeFromViewSpaceToLayoutSpace(Shape shape,
			VisualizationServer<V, E> viewer) {

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		return transformer.inverseTransform(shape);
	}

	private static <V, E> Shape translateShapeFromGraphSpaceToViewSpace(Shape shapeInGraphSpace,
			VisualizationServer<V, E> viewer) {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		return transformer.transform(Layer.VIEW, shapeInGraphSpace);
	}

	private static <V, E> Point getVertexCenterPointInLayoutSpace(VisualizationServer<V, E> viewer,
			V vertex) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Point2D vertexCenter = layout.apply(vertex);
		return new Point((int) vertexCenter.getX(), (int) vertexCenter.getY());
	}

	// Note: vertex relative means that the value is from inside the vertex, or the vertex's
	//       coordinate space (like a component that is inside the vertex), where it's 
	//       coordinate values are relative to the component's parent.
	public static <V, E> Rectangle translateRectangleFromVertexRelativeSpaceToViewSpace(
			VisualizationServer<V, E> viewer, V vertex, Rectangle rectangle) {

		Point locationInViewSpace = translatePointFromVertexRelativeSpaceToViewSpace(viewer, vertex,
			rectangle.getLocation());

		// translate the size of the rectangle
		Shape transformedShape = translateShapeFromGraphSpaceToViewSpace(rectangle, viewer);
		Rectangle newBounds = transformedShape.getBounds();
		newBounds.setLocation(locationInViewSpace);
		return newBounds;
	}

	public static <V, E> Rectangle translateRectangleFromLayoutSpaceToViewSpace(
			VisualizationServer<V, E> viewer, Rectangle rectangle) {

		Point locationInViewSpace =
			translatePointFromLayoutSpaceToViewSpace(rectangle.getLocation(), viewer);

		// translate the size of the rectangle
		Shape transformedShape = translateShapeFromLayoutSpaceToViewSpace(rectangle, viewer);
		Rectangle newBounds = transformedShape.getBounds();
		newBounds.setLocation(locationInViewSpace);
		return newBounds;
	}

	public static <V, E> V getVertexFromPointInViewSpace(VisualizationServer<V, E> viewer,
			Point point) {
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (pickSupport == null) {
			return null;
		}

		Layout<V, E> layout = viewer.getGraphLayout();
		return pickSupport.getVertex(layout, point.getX(), point.getY());
	}

	/** 
	 * Get the upper-left point of vertex in the view space (Java component space)
	 *  
	 * @param viewer the viewer containing the UI 
	 * @param vertex the vertex
	 * @return the upper-left point of the vertex
	 */
	public static <V, E> Point getPointInViewSpaceForVertex(VisualizationServer<V, E> viewer,
			V vertex) {

		Point vertexUpperLeftCornerInGraphSpace =
			getVertexUpperLeftCornerInGraphSpace(viewer, vertex);
		return translatePointFromGraphSpaceToViewSpace(vertexUpperLeftCornerInGraphSpace, viewer);
	}

	public static <V, E> Point translatePointFromVertexRelativeSpaceToViewSpace(
			VisualizationServer<V, E> viewer, V vertex, Point startPoint) {

		Point vertexUpperLeftCornerInGraphSpace =
			getVertexUpperLeftCornerInGraphSpace(viewer, vertex);

		int relativeX = vertexUpperLeftCornerInGraphSpace.x + startPoint.x;
		int relativeY = vertexUpperLeftCornerInGraphSpace.y + startPoint.y;
		Point pointInGraphSpace = new Point(relativeX, relativeY);

		return translatePointFromGraphSpaceToViewSpace(pointInGraphSpace, viewer);
	}

	public static <V, E> E getEdgeFromPointInViewSpace(VisualizationServer<V, E> viewer,
			Point point) {
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (pickSupport == null) {
			return null;
		}

		Layout<V, E> layout = viewer.getGraphLayout();
		return pickSupport.getEdge(layout, point.getX(), point.getY());
	}

	public static Double getScaleRatioToFitInDimension(Dimension currentSize,
			Dimension targetSize) {

		if (currentSize.width < targetSize.width && currentSize.height < targetSize.height) {
			// go to max zoom
			return 1.0;
		}

		if (currentSize.width > targetSize.width || currentSize.height > targetSize.height) {
			return zoomOutRatio(currentSize, targetSize);
		}

		return null;
	}

	private static Double zoomOutRatio(Dimension currentSize, Dimension targetSize) {
		Double widthRatio = (double) targetSize.width / (double) currentSize.width;
		Double heightRatio = (double) targetSize.height / (double) currentSize.height;

		return (widthRatio < heightRatio) ? widthRatio : heightRatio;
	}

	public static <V, E> void setGraphScale(VisualizationServer<V, E> viewer, double scale) {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		MutableTransformer viewTransformer = multiLayerTransformer.getTransformer(Layer.VIEW);
		viewTransformer.setScale(scale, scale, new Point(0, 0));
	}

	public static <V, E> void adjustEdgePickSizeForZoom(VisualizationServer<V, E> viewer) {
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (!(pickSupport instanceof ShapePickSupport<?, ?>)) {
			return;
		}
		ShapePickSupport<V, E> shapePickSupport = (ShapePickSupport<V, E>) pickSupport;

		Double graphScale = getGraphScale(viewer);
		float adjustedPickSize = (float) (UNSCALED_EDGE_PICK_SIZE / graphScale);
		shapePickSupport.setPickSize(adjustedPickSize);
	}

	/**
	 * Moves the selected vertices to the end of the list of vertices so that when picked (or 
	 * painted), we will prefer the selected vertices, since we have configured the algorithms for
	 * the graph stuff to prefer the last accessed vertex (like when picking and painting).
	 * 
	 * @param vertices the vertices to order
	 * @return the given vertices, ordered by selected/emphasized state
	 */
	public static <V extends VisualVertex> List<V> createCollectionWithZOrderBySelection(
			Collection<V> vertices) {
		List<V> list = new LinkedList<>();
		List<V> selectedList = new LinkedList<>();
		for (V vertex : vertices) {
			double emphasis = vertex.getEmphasis();
			if (vertex.isSelected() || emphasis != 0) {
				selectedList.add(vertex);
			}
			else {
				list.add(vertex);
			}
		}

		list.addAll(selectedList);

		return list;
	}

	public static Shape createHollowEgdeLoop() {
		return doCreateHollowEgdeLoop().getShape();
	}

	private static GraphLoopShape doCreateHollowEgdeLoop() {
		// draw an approximated circle around, and then back again
		// to make a hollow shape (so shape detection misses in middle)

		/*
		
		 Coordinate space is on a graph with 1 unit in each direction
		
				-1
		
		        |
		        |
		        |
		        |
		-1 ------------- 1
		 	    |
		 	    |
		 	    |
		 	    |
		
		 	    1
		
		
		 Origin in Java2D space--center of the graph (note that positive y is down and not up)
		
		0,0
		 ------------      1) Move up by the radius amount so we can then go down and to the left
		 |                    with each pass until we head back in the other direction.
		 |
		 |
		 |
		 |
		 |                                -.75 (assume r = 0.75)
		 								  |
		 								  |
		 								  |
		 								  |
		 							    0 -------
		
		 				   2) Move backwards (-x) and down (to 0 from -y)
		
		 				   						|
		 				   						|
		 				            -.75 -------|- 0
		 				   						|
		 				   						|
		
		
		 		 	    Each new point is the last two values in the method call
		
		 */

		// NOTE: this cubic bezier path approximates a circle
		GeneralPath path = new GeneralPath();
		float r = EDGE_LOOP_RADIUS;
		float k = BEZIER_CONTROL_POINT;

		path.moveTo(0, -r);
		path.curveTo(-k, -r, -r, -k, -r, 0);
		path.curveTo(-r, k, -k, r, 0, r);
		path.curveTo(k, r, r, k, r, 0);
		path.curveTo(r, -k, k, -r, 0, -r);

		// go back the other direction so that the shape is not an entire circle, but just the
		// outline of a circle
		path.curveTo(k, -r, r, -k, r, 0);
		path.curveTo(r, k, k, r, 0, r);
		path.curveTo(-k, r, -r, k, -r, 0);
		path.curveTo(-r, -k, -k, -r, 0, -r);

		return new GraphLoopShape(path, r);
	}

	/**
	 * Creates a self-loop edge to be used with a vertex that calls itself.  The returned shape
	 * is hollow (not a filled loop) so that mouse hit detection does not occur in the middle of
	 * the circle.
	 *
	 * @param vertexShape The shape of the vertex for which the edge is being created.
	 * @param x The x coordinate of the vertex
	 * @param y The y coordinate of the vertex
	 * @return a self-loop edge to be used with a vertex that calls itself.
	 */
	public static Shape createHollowEgdeLoopInGraphSpace(Shape vertexShape, double x, double y) {
		GraphLoopShape fgLoopShape = doCreateHollowEgdeLoop();
		Shape edgeShape = fgLoopShape.getShape();
		return createEgdeLoopInGraphSpace(edgeShape, vertexShape, x, y);
	}

	/**
	 * Creates a loop shape for a vertex that calls itself.  The loop is transformed to graph space,
	 * which includes updating the size and location of the loop to be relative to
	 * the vertex.
	 *
	 * @param vertexShape The shape of the vertex for which the edge is being created.
	 * @param x The x coordinate of the vertex
	 * @param y The y coordinate of the vertex
	 * @return a loop shape for a vertex that calls itself.
	 */
	public static Shape createEgdeLoopInGraphSpace(Shape vertexShape, double x, double y) {

		// NOTE: this cubic bezier path approximates a circle
		GeneralPath path = new GeneralPath();
		float r = EDGE_LOOP_RADIUS;
		float k = BEZIER_CONTROL_POINT;

		path.reset();
		path.moveTo(0, -r);
		path.curveTo(-k, -r, -r, -k, -r, 0);
		path.curveTo(-r, k, -k, r, 0, r);
		path.curveTo(k, r, r, k, r, 0);
		path.curveTo(r, -k, k, -r, 0, -r);

		return createEgdeLoopInGraphSpace(path, vertexShape, x, y);
	}

	/**
	 * Transforms the given edge loop shape to graph space, which includes updating
	 * the size and location of the loop to be relative to the vertex.
	 *
	 * @param edgeLoopShape The shape to transform
	 * @param vertexShape The shape of the vertex for which the edge is being created
	 * @param x The x coordinate of the vertex
	 * @param y The y coordinate of the vertex
	 * @return the transformed edge loop shape
	 */
	public static Shape createEgdeLoopInGraphSpace(Shape edgeLoopShape, Shape vertexShape, double x,
			double y) {

		/*
		 	x, y - vertex coordinates; these are the center of the vertex shape
		 	vertexShape - the is the shape of the vertex; it will be centered over the x,y
		 	
		 		shape x,y
		 				---------
		 				|       |
		 				|  x,y (|)   edge circle, clipped by the vertex
		 				|       |
		 				---------
		 	
		 */

		// note: the edge shape will be drawn around its center
		Rectangle2D b = vertexShape.getBounds2D();
		double vWidth = b.getWidth();
		double vHeight = b.getHeight();

		double scale = .2; // edge size as a proportion of vertex size

		/*
		 	This code allows the edge position to move closer to the shape when not using 
		 	a rectangular shape.   If we ever have unusual shapes, then this may be worth using.
		 	For now, it seems excessive to perform the math, as this code is currently called
		 	for each loop edge, for each paint.   If we ever cache edge info, this is available.
		
		 	
		 	// 
			// The 'endX' is the right edge of the *rectangle bounds* of the vertex.  The actual
			// shape of the vertex may not be rectangular.  So, keep moving the edge shape closer
			// to the vertex until it is slightly obscured (as noted above).
			//
			double move = .1;
			Point2D p = new Point2D.Double(endX, y);
			while (p.getX() > x) {
		
				if (vertexShape.contains(p)) {
					break;
				}
		
				double offset = move * radius;
				p.setLocation(endX - offset, y);
				move += .1;
			}
			double edgeX = p.getX();		  
		 */

		double radius = vHeight * scale;
		double diameter = radius * 2;

		// hide some of the circle so it appears as the edge enters and exits the vertex
		double hiddenAmount = diameter * .30;
		double halfVertex = (vWidth / 2); // divide by 2; the vertex is centered
		double vertexEndX = x + halfVertex;

		double edgeX = vertexEndX + radius - hiddenAmount;
		AffineTransform xform = AffineTransform.getTranslateInstance(edgeX, y);
		xform.scale(radius, radius);
		return xform.createTransformedShape(edgeLoopShape);
	}

	public static <V, E> Shape getEdgeShapeInGraphSpace(VisualizationServer<V, E> viewer, E e) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Pair<V> pair = layout.getGraph().getEndpoints(e);
		V startVertex = pair.getFirst();
		V endVertex = pair.getSecond();

		Point2D startVertexCenter = getVertexCenterPointInGraphSpace(viewer, startVertex);
		if (startVertexCenter == null) {
			return null;
		}

		Point2D endVertexCenter = getVertexCenterPointInGraphSpace(viewer, endVertex);
		if (endVertexCenter == null) {
			return null;
		}

		boolean isLoop = startVertex.equals(endVertex);
		double startX = (float) startVertexCenter.getX();
		double startY = (float) startVertexCenter.getY();
		double endX = (float) endVertexCenter.getX();
		double endY = (float) endVertexCenter.getY();

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		if (isLoop) {
			//
			// Our edge loops are sized and positioned according to the shared
			// code in the utils class.  We do this so that our hit detection matches our rendering.
			//
			Function<? super V, Shape> vertexShapeTransformer =
				renderContext.getVertexShapeTransformer();
			Shape vertexShape = getVertexShapeForEdge(endVertex, vertexShapeTransformer);
			return createHollowEgdeLoopInGraphSpace(vertexShape, startX, startY);
		}

		// translate the edge from 0,0 to the starting vertex point
		AffineTransform xform = AffineTransform.getTranslateInstance(startX, startY);
		Shape edgeShape = renderContext.getEdgeShapeTransformer().apply(e);

		double deltaX = endX - startX;
		double deltaY = endY - startY;

		// rotate the edge to the angle between the vertices
		double theta = Math.atan2(deltaY, deltaX);
		xform.rotate(theta);

		// stretch the edge to span the distance between the vertices
		double dist = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
		xform.scale(dist, 1.0f);

		// apply the transformations; converting the given shape from model space into graph space
		return xform.createTransformedShape(edgeShape);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static <V> Shape getVertexShapeForEdge(V v, Function<? super V, Shape> vertexShaper) {
		if (vertexShaper instanceof VisualGraphVertexShapeTransformer) {
			if (v instanceof VisualVertex) {
				VisualVertex vv = (VisualVertex) v;

				// Note: it is a bit odd that we 'know' to use the compact shape here for 
				// 		 hit detection, but this is how the edge is painted, so we want the 
				//       view to match the mouse.
				return ((VisualGraphVertexShapeTransformer) vertexShaper).transformToCompactShape(
					vv);
			}
		}
		return vertexShaper.apply(v);
	}

	private static <V, E> Point2D getVertexCenterPointInGraphSpace(VisualizationServer<V, E> viewer,
			V vertex) {
		Layout<V, E> layout = viewer.getGraphLayout();
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		Point2D vertex1CenterInLayoutSpace = layout.apply(vertex);
		return transformer.transform(Layer.LAYOUT, vertex1CenterInLayoutSpace);
	}

	public static <V, E> Point2D getVertexCenterPointInViewSpace(VisualizationServer<V, E> viewer,
			V v) {
		Layout<V, E> layout = viewer.getGraphLayout();
		Point2D centerInLayoutSpace = layout.apply(v);
		Point viewSpacePoint =
			translatePointFromLayoutSpaceToViewSpace(centerInLayoutSpace, viewer);
		return viewSpacePoint;
	}

	public static <V, E> Point2D.Double getVertexOffsetFromLayoutCenter(
			VisualizationServer<V, E> viewer, V vertex) {
		Point vertexPoint = getVertexCenterPointInLayoutSpace(viewer, vertex);
		return getOffsetFromCenterInLayoutSpace(viewer, vertexPoint);
	}

	public static <V, E> Point2D.Double getVertexOffsetFromLayoutCenterTop(
			VisualizationServer<V, E> viewer, V vertex) {
		return getVertexOffsetFromCenterTopInLayoutSpace(viewer, vertex);
	}

	public static <V, E> Point2D.Double getOffsetFromCenterForPointInViewSpace(
			VisualizationServer<V, E> viewer, Point2D point) {

		Point pointInLayoutSpace = translatePointFromViewSpaceToLayoutSpace(point, viewer);
		return getOffsetFromCenterInLayoutSpace(viewer, pointInLayoutSpace);
	}

	public static <V, E> Point2D.Double getOffsetFromCenterInLayoutSpace(
			VisualizationServer<V, E> viewer, Point pointInLayoutSpace) {

		Point2D viewCenter = viewer.getCenter();
		Point layoutCenterInLayoutSpace =
			translatePointFromViewSpaceToLayoutSpace(viewCenter, viewer);
		double offsetX = layoutCenterInLayoutSpace.getX() - pointInLayoutSpace.getX();
		double offsetY = layoutCenterInLayoutSpace.getY() - pointInLayoutSpace.getY();
		return new Point2D.Double(offsetX, offsetY);
	}

	private static <V, E> Point2D.Double getVertexOffsetFromCenterTopInLayoutSpace(
			VisualizationServer<V, E> viewer, V vertex) {

		//
		// We need an offset from the current vertex to the center top of the viewer
		//
		Rectangle vertexBoundsInViewSpace = getVertexBoundsInViewSpace(viewer, vertex);
		Point vertexLocationInViewSpace = vertexBoundsInViewSpace.getLocation();

		// Move our point a bit: we want x to be the center value, as we are getting an offset
		// 						 from the viewer's center x
		double centerX =
			vertexLocationInViewSpace.getX() + ((int) vertexBoundsInViewSpace.getWidth() >> 1);
		vertexLocationInViewSpace.setLocation(centerX, vertexLocationInViewSpace.getY());

		Point2D viewCenter = viewer.getCenter();
		int yWithPadding = 10;
		viewCenter.setLocation(viewCenter.getX(), yWithPadding); // move to the top of the view space

		Point vertexPointInLayoutSpace =
			translatePointFromViewSpaceToLayoutSpace(vertexLocationInViewSpace, viewer);
		Point layoutCenterInLayoutSpace =
			translatePointFromViewSpaceToLayoutSpace(viewCenter, viewer);

		double offsetX = layoutCenterInLayoutSpace.getX() - vertexPointInLayoutSpace.getX();
		double offsetY = layoutCenterInLayoutSpace.getY() - vertexPointInLayoutSpace.getY();
		return new Point2D.Double(offsetX, offsetY);
	}

	public static <V, E> Double getGraphScale(VisualizationServer<V, E> vv) {
		RenderContext<V, E> context = vv.getRenderContext();
		MultiLayerTransformer transformer = context.getMultiLayerTransformer();
		MutableTransformer layoutTransformer = transformer.getTransformer(Layer.LAYOUT);
		MutableTransformer viewTransformer = transformer.getTransformer(Layer.VIEW);
		double modelScale = layoutTransformer.getScale();
		double viewScale = viewTransformer.getScale();
		return modelScale * viewScale;
	}

	public static <V, E> boolean isScaledPastVertexInteractionThreshold(
			VisualizationServer<V, E> viewer) {
		double scale = getGraphScale(viewer);
		return scale < INTERACTION_ZOOM_THRESHOLD;
	}

	public static <V extends VisualVertex, E extends VisualEdge<V>> Point getGraphCenterInLayoutSpace(
			VisualizationServer<V, E> viewer) {
		Rectangle graphBounds = getTotalGraphSizeInLayoutSpace(viewer);
		return new Point((int) graphBounds.getCenterX(), (int) graphBounds.getCenterY());
	}

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> 
		Rectangle getTotalGraphSizeInLayoutSpace(VisualizationServer<V, E> viewer) {
	//@formatter:on

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> theGraph = layout.getGraph();
		Collection<V> vertices = theGraph.getVertices();
		Collection<E> edges = theGraph.getEdges();

		Function<V, Rectangle> vertexToBounds = createVertexToBoundsTransformer(viewer);

		if (!layoutUsesEdgeArticulations(layout)) {
			Rectangle bounds = getBoundsForVerticesInLayoutSpace(vertices, vertexToBounds);
			return bounds;
		}

		Function<E, List<Point2D>> edgeToArticulations = e -> e.getArticulationPoints();
		return getTotalGraphSizeInLayoutSpace(vertices, edges, vertexToBounds, edgeToArticulations);
	}

	//@formatter:off
	private static <V extends VisualVertex, E extends VisualEdge<V>> Function<V, Rectangle> 
		createVertexToBoundsTransformer(VisualizationServer<V, E> viewer) {
	//@formatter:on

		RenderContext<V, E> context = viewer.getRenderContext();
		Function<? super V, Shape> shapeTransformer = context.getVertexShapeTransformer();
		Layout<V, E> layout = viewer.getGraphLayout();
		Function<V, Rectangle> transformer = v -> {

			Shape s = shapeTransformer.apply(v);
			Rectangle bounds = s.getBounds();
			Point2D p = layout.apply(v);

			// Note: we use the raw x/y of the layout; the view code will center the vertices
			bounds.setLocation(new Point((int) p.getX(), (int) p.getY()));
			return bounds;
		};
		return transformer;
	}

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> 
			Rectangle getTotalGraphSizeInLayoutSpace(
												Collection<V> vertices,
												Collection<E> edges,
												Function<V, Rectangle> vertexToBounds,
											    Function<E, List<Point2D>> edgeToArticulations) {
	//@formatter:on

		Rectangle vertexBounds = getBoundsForVerticesInLayoutSpace(vertices, vertexToBounds);

		double largestX = vertexBounds.x + vertexBounds.width;
		double largestY = vertexBounds.y + vertexBounds.height;
		double smallestX = vertexBounds.x;
		double smallestY = vertexBounds.y;

		for (E e : edges) {

			List<Point2D> articulationPoints = edgeToArticulations.apply(e);
			for (Point2D point : articulationPoints) {
				double vertexX = point.getX();
				double vertexY = point.getY();

				double componentMinX = vertexX - EXTRA_LAYOUT_COLUMN_SPACING / 2;
				double componentMinY = vertexY - EXTRA_LAYOUT_ROW_SPACING / 2;
				double componentMaxX = vertexX + EXTRA_LAYOUT_COLUMN_SPACING / 2;
				double componentMaxY = vertexY + EXTRA_LAYOUT_ROW_SPACING / 2;

				smallestX = Math.min(componentMinX, smallestX);
				smallestY = Math.min(componentMinY, smallestY);
				largestX = Math.max(componentMaxX, largestX);
				largestY = Math.max(componentMaxY, largestY);
			}
		}

		int width = (int) (largestX - smallestX);
		int height = (int) (largestY - smallestY);
		return new Rectangle((int) smallestX, (int) smallestY, width, height);
	}

	/**
	 * Returns a rectangle that contains all give vertices
	 * 
	 * @param viewer the viewer containing the UI
	 * @param vertices the vertices 
	 * @return a rectangle that contains all give vertices
	 */
	public static <V, E> Rectangle getBoundsForVerticesInLayoutSpace(
			VisualizationServer<V, E> viewer, Collection<V> vertices) {

		Layout<V, E> layout = viewer.getGraphLayout();
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		Function<? super V, Shape> shapeTransformer = renderContext.getVertexShapeTransformer();

		Function<V, Rectangle> transformer = v -> {

			Shape shape = shapeTransformer.apply(v);
			Rectangle bounds = shape.getBounds();
			Point2D point = layout.apply(v);
			bounds.setLocation(new Point((int) point.getX(), (int) point.getY()));
			return bounds;
		};
		return getBoundsForVerticesInLayoutSpace(vertices, transformer);
	}

	/**
	 * Returns a rectangle that contains all vertices, in the layout space
	 * 
	 * @param vertices the vertices for which to calculate the bounds
	 * 
	 * @param vertexToBounds a function that can turn a single vertex into a rectangle
	 * @return the bounds
	 */
	public static <V, E> Rectangle getBoundsForVerticesInLayoutSpace(Collection<V> vertices,
			Function<V, Rectangle> vertexToBounds) {

		if (vertices.isEmpty()) {
			throw new IllegalStateException("No vertices for which to find bounds!");
		}

		double largestX = 0;
		double largestY = 0;

		double smallestX = Integer.MAX_VALUE;
		double smallestY = Integer.MAX_VALUE;

		for (V v : vertices) {

			Rectangle bounds = vertexToBounds.apply(v);

			int halfWidth = bounds.width >> 1;
			int halfHeight = bounds.height >> 1;
			double vertexX = bounds.getX();
			double vertexY = bounds.getY();

			double componentMinX = vertexX - halfWidth;
			double componentMinY = vertexY - halfHeight;
			double componentMaxX = vertexX + halfWidth;
			double componentMaxY = vertexY + halfHeight;

			smallestX = Math.min(componentMinX, smallestX);
			smallestY = Math.min(componentMinY, smallestY);
			largestX = Math.max(componentMaxX, largestX);
			largestY = Math.max(componentMaxY, largestY);
		}

		int width = (int) (largestX - smallestX);
		int height = (int) (largestY - smallestY);
		return new Rectangle((int) smallestX, (int) smallestY, width, height);
	}

	public static void addPaddingToRectangle(int padding, Rectangle rectangle) {
		rectangle.x -= padding;
		rectangle.y -= padding;
		rectangle.width += (padding * 2);
		rectangle.height += (padding * 2);
	}

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> 
		boolean layoutUsesEdgeArticulations(Layout<V, E> graphLayout) {
	//@formatter:on

		VisualGraphLayout<?, ?> layout = getVisualGraphLayout(graphLayout);
		if (layout == null) {
			return false;
		}
		return layout.usesEdgeArticulations();
	}

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> 
		VisualGraphLayout<V, E> getVisualGraphLayout(Layout<V, E> graphLayout) {
	//@formatter:on

		Layout<V, E> layout = graphLayout;
		while (layout instanceof LayoutDecorator) {
			layout = ((LayoutDecorator<V, E>) layout).getDelegate();
		}

		if (!(layout instanceof VisualGraphLayout)) {
			return null;
		}

		return (VisualGraphLayout<V, E>) layout;
	}

	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> Collection<V> 
		getVerticesOfHoveredEdges(Graph<V, E> graph) { 
	//@formatter:on

		return getVerticesOfSelectedOrHoveredEdges(graph, true);
	}

	/**
	 * Returns a collection of vertices that are incident to selected edges.
	 * 
	 * @param graph the graph from which to retrieve vertices
	 * @return a collection of vertices that are incident to selected edges.
	 */
	//@formatter:off
	public static <V extends VisualVertex, E extends VisualEdge<V>> Collection<V> 
		getVerticesOfSelectedEdges(Graph<V, E> graph) {
	//@formatter:on

		return getVerticesOfSelectedOrHoveredEdges(graph, false);
	}

	//@formatter:off
	private static <V extends VisualVertex, E extends VisualEdge<V>> Collection<V> 
		getVerticesOfSelectedOrHoveredEdges(Graph<V, E> graph, boolean useHover) {
	//@formatter:on

		List<V> result = new LinkedList<>();
		Collection<E> edges = graph.getEdges();
		LinkedList<E> filteredEdges = new LinkedList<>();
		if (useHover) {
			for (E edge : edges) {
				if (edge.isInHoveredVertexPath()) {
					filteredEdges.add(edge);
				}
			}
		}
		else {
			for (E edge : edges) {
				if (edge.isSelected()) {
					filteredEdges.add(edge);
				}
			}
		}

		Collection<V> vertices = GraphAlgorithms.toVertices(filteredEdges);
		result.addAll(vertices);
		return result;
	}

}
