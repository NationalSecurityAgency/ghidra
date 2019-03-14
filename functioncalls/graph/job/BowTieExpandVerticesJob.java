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
package functioncalls.graph.job;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.*;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.RenderContext;
import functioncalls.graph.*;
import functioncalls.graph.layout.BowTieLayout;
import ghidra.graph.job.AbstractGraphTransitionJob;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.util.Msg;

/**
 * A graph job to layout a given set of graph vertices.  Most of the work for this class is
 * done in {@link #arrangeNewVertices()}.
 * 
 * <P>This class is handed a group of edges to processes.  In this group there are vertices that
 * do not need to be arranged, referred to as the <tt>existing</tt> vertices.  This 
 * classes uses {@link VertexCollection} to find and store the new vertices that need
 * to be arranged. 
 */
public class BowTieExpandVerticesJob extends AbstractGraphTransitionJob<FcgVertex, FcgEdge> {

	private boolean incoming;
	private FcgLevel expandingLevel;
	private FcgExpandingVertexCollection newVertexCollection;

	/**
	 * Constructor
	 * 
	 * @param viewer the graph viewer
	 * @param newVertexCollection the collection of new vertices and edges being addeds
	 * @param useAnimation true to use animation
	 */
	public BowTieExpandVerticesJob(GraphViewer<FcgVertex, FcgEdge> viewer,
			FcgExpandingVertexCollection newVertexCollection, boolean useAnimation) {
		super(viewer, useAnimation);

		this.newVertexCollection = newVertexCollection;
		this.incoming = newVertexCollection.isIncoming();
		this.expandingLevel = newVertexCollection.getExpandingLevel();

		if (!(graphLayout instanceof BowTieLayout)) {
			throw new IllegalArgumentException("The current graph layout must be the " +
				BowTieLayout.class.getSimpleName() + " to use this job");
		}

		Msg.trace(this,
			"\nBow Tie Expand Job - new vertices: " + newVertexCollection.getNewVertices());

		// for debug
		// duration = 5000;
	}

	@Override
	protected boolean isTooBigToAnimate() {
		return graph.getVertexCount() > 1000; // not sure about the best number here
	}

	@Override
	protected void updateOpacity(double percentComplete) {

		/*
		 	Aesthetic Note:  due to the colors used in the graph in conjunction with the
		 	alpha used here, when using the same opacity for the vertices and the edges, the
		 	edges can be seen through the vertices, which looks bad.   To fix this, have the
		 	edges be less visible until the vertices are more opaque.
		 */
		double x = percentComplete;
		double x2 = x * x;  					 // change slower than x
		double remaining = 1 - percentComplete;  // start opacity towards the end 
		double y = x2 - remaining;

		//Msg.debug(this, String.format("%%: %.3f - x^2: %.3f - remaining: %.3f - edge alpha: %.3f",
		//	percentComplete, (x * x), remaining, y));

		Set<FcgVertex> newVertices = newVertexCollection.getNewVertices();

		double vertexAlpha = x;
		double edgeAlpha = Math.max(y, 0);
		for (FcgVertex v : newVertices) {
			v.setAlpha(vertexAlpha);
		}

		Iterable<FcgEdge> newEdges = newVertexCollection.getNewEdges();
		for (FcgEdge edge : newEdges) {
			edge.setAlpha(edgeAlpha);
		}
	}

	@Override
	public boolean canShortcut() {
		return true;
	}

	@Override
	public void shortcut() {
		isShortcut = true;

		if (vertexLocations.isEmpty()) {
			// have not yet initialized; do so now before the final locations are applied
			initializeVertexLocations();
		}

		stop();
	}

	@Override
	protected void initializeVertexLocations() {

		Map<FcgVertex, TransitionPoints> destinationLocations = createDestinationLocation();
		vertexLocations.putAll(destinationLocations);
	}

	private Map<FcgVertex, TransitionPoints> createDestinationLocation() {

		// note: both collections of vertices are sorted
		Map<FcgVertex, Point2D> finalDestinations = arrangeNewVertices();

		Map<FcgVertex, TransitionPoints> transitions = new HashMap<>();
		FcgLevel parentLevel = expandingLevel.parent();
		Iterable<FcgEdge> newEdges = newVertexCollection.getNewEdges();
		Set<FcgVertex> newVertices = newVertexCollection.getNewVertices();
		for (FcgEdge e : newEdges) {

			FcgVertex newVertex = incoming ? e.getStart() : e.getEnd();
			if (!finalDestinations.containsKey(newVertex)) {
				continue; // this implies the edges is between 2 existing vertices
			}

			if (!newVertices.contains(newVertex)) {
				continue; // a new edge to an existing vertex
			}

			FcgVertex existingVertex = incoming ? e.getEnd() : e.getStart();
			FcgLevel existingLevel = existingVertex.getLevel();
			if (!existingLevel.equals(parentLevel)) {
				// Only the parent level can be the source of the transition.  This ensures
				// that the animation starts at the level that was expanded and not at some
				// other level in the graph that happened to have an edge to the new node.
				continue;
			}

			Point2D start = (Point2D) toLocation(existingVertex).clone();
			Point2D end = finalDestinations.get(newVertex);

			TransitionPoints trans = new TransitionPoints(start, end);
			transitions.put(newVertex, trans);
		}

		return transitions;
	}

	private Map<FcgVertex, Point2D> arrangeNewVertices() {

		/*
		 	Add the new row above (or below) the existing row that is being expanded.  So,
		 	the new graph will appear as so:
		 	
		 		v3.1  v3.2   v3.4  v3.5   v3.6
		 				v2.1      v2.2
		 					 v1.1
		 					 
		 	Where the '3.x' nodes are those being added.  They will be centered in relation to
		 	the existing row.
		 	
		 */

		BowTieLayout bowTie = (BowTieLayout) graphLayout;
		boolean isCondensed = bowTie.isCondensedLayout();
		int widthPadding = isCondensed ? GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING_CONDENSED
				: GraphViewerUtils.EXTRA_LAYOUT_COLUMN_SPACING;

		// More space the further away from center, for aesthetics/readability (as the graph 
		// gets larger, more edges are added, cluttering up the display).
		widthPadding *= expandingLevel.getDistance();
		int heightPadding = calculateHeightPadding(isCondensed);

		FcgLevel parentLevel = expandingLevel.parent();
		List<FcgVertex> parentLevelVertices = newVertexCollection.getVerticesByLevel(parentLevel);
		if (parentLevelVertices.isEmpty()) {
			// this can happen if all the new edges being added already exist in the graph
			// at a different level than the parent
			return Collections.emptyMap();
		}

		Rectangle existingRowBounds = getBounds(parentLevelVertices);
		Msg.trace(this, "existing row bounds " + existingRowBounds);
		double existingY = existingRowBounds.y;
		double existingCenterX = existingRowBounds.x + (existingRowBounds.width / 2);

		// Layout all vertices at the new level, even the hidden ones, so the new ones fit
		// within the overall level.  This allows future expansions to put the new nodes in 
		// the correct spot.
		List<FcgVertex> allLevelVertices = newVertexCollection.getAllVerticesAtNewLevel();
		double newRowWidth = getWidth(allLevelVertices, widthPadding);
		double newRowHeight = getHeight(allLevelVertices);
		double newRowX = existingCenterX - (newRowWidth / 2);

		double newRowY = 0;
		if (newVertexCollection.isIncoming()) {
			newRowY = existingY - newRowHeight - heightPadding;
		}
		else {
			newRowY = existingY + existingRowBounds.height + heightPadding;
		}

		Msg.trace(this, "new row bounds " +
			new Rectangle2D.Double(newRowX, newRowY, newRowWidth, newRowHeight));

		Map<FcgVertex, Point2D> locations = getExistingLocations(allLevelVertices);
		if (!locations.isEmpty()) {
			// use the existing locations so that the nodes appear where the user expects
			return locations;
		}

		RenderContext<FcgVertex, FcgEdge> renderContext = viewer.getRenderContext();
		Function<? super FcgVertex, Shape> shaper = renderContext.getVertexShapeTransformer();

		double x = newRowX;
		double y = newRowY;

		int n = allLevelVertices.size();
		for (int i = 0; i < n; i++) {
			FcgVertex v = allLevelVertices.get(i);
			Rectangle myBounds = shaper.apply(v).getBounds();
			double myHalf = myBounds.width / 2;

			double nextHalf = 0;
			boolean isLast = i == n - 1;
			if (!isLast) {
				FcgVertex nextV = allLevelVertices.get(i + 1);
				Rectangle nextBounds = shaper.apply(nextV).getBounds();
				nextHalf = nextBounds.width / 2;
			}

			Point2D p = new Point2D.Double(x, y);
			locations.put(v, p);

			double vWidth = myHalf + widthPadding + nextHalf;
			Msg.trace(this, v + " at x,width: " + x + "," + vWidth);
			x += vWidth;
		}

		return locations;
	}

	private int calculateHeightPadding(boolean isCondensed) {

		// give each successive level
		int basePadding = isCondensed ? GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING_CONDENSED
				: GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING;

		double separationFactor = expandingLevel.getDistance();

		/*
		 	Let's scale the distance between 2 rows.  As the level increases so too should the
		 	distance, based upon how busyness (how many edges) of the new level being added.
		 		-If the new level is not busy, then keep the standard distance;
		 		-If the new level is busy, increase the y-distance, up to the max, based upon
		 		 the busyness 
		 	
		 */
		List<FcgVertex> allLevelVertices = newVertexCollection.getAllVerticesAtNewLevel();
		int count = allLevelVertices.size();

		// grow each layer more than linear to add space for the edges
		double to = 1.25; // 1.5;
		double power = Math.pow(separationFactor, to);
		int maxPadding = (int) (basePadding * power);

		// range from 0-1 (%) based on edge count, with 20 being the high-side
		int delta = maxPadding - basePadding;
		double percent = Math.min(count / 20f, 1);
		int padding = basePadding + (int) (delta * percent);
		return padding;
	}

	private Map<FcgVertex, Point2D> getExistingLocations(List<FcgVertex> vertices) {

		Map<FcgVertex, Point2D> locations = new HashMap<>();
		for (FcgVertex v : vertices) {
			Point2D p = toLocation(v);
			if (p.getX() == 0 && p.getY() == 0) {
				// no location for this vertex--we have to build them
				return new HashMap<>();
			}
			locations.put(v, (Point2D) p.clone());
		}
		return locations;
	}

	private Rectangle getBounds(List<FcgVertex> vertices) {
		RenderContext<FcgVertex, FcgEdge> renderContext = viewer.getRenderContext();
		Function<? super FcgVertex, Shape> shaper = renderContext.getVertexShapeTransformer();

		Layout<FcgVertex, FcgEdge> layout = viewer.getGraphLayout();

		Rectangle area = null;
		for (FcgVertex v : vertices) {
			Rectangle bounds = shaper.apply(v).getBounds();
			Point2D loc = layout.apply(v);
			int x = (int) loc.getX();
			int y = (int) loc.getY();
			// do we need to compensate for vertex centering (like is done in the default layout)?		
			//	x -= (bounds.width / 2);
			//	y -= (bounds.height / 2);
			bounds.setLocation(x, y);
			if (area == null) {
				area = bounds; // initialize
			}
			area.add(bounds);
		}

		return area;
	}

	private int getWidth(List<FcgVertex> vertices, int widthPadding) {

		RenderContext<FcgVertex, FcgEdge> renderContext = viewer.getRenderContext();
		Function<? super FcgVertex, Shape> shaper = renderContext.getVertexShapeTransformer();

		int width = 0;
		for (FcgVertex v : vertices) {
			width += shaper.apply(v).getBounds().width + widthPadding;
		}

		return width;
	}

	private int getHeight(List<FcgVertex> vertices) {

		RenderContext<FcgVertex, FcgEdge> renderContext = viewer.getRenderContext();
		Function<? super FcgVertex, Shape> shaper = renderContext.getVertexShapeTransformer();

		int height = 0;
		for (FcgVertex v : vertices) {
			height = Math.max(height, shaper.apply(v).getBounds().height);
		}

		return height;
	}
}
