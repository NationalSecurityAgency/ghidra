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

import java.awt.Point;

import edu.uci.ics.jung.visualization.*;
import ghidra.framework.options.SaveState;

/**
 * An object that allows for storing and restoring of graph perspective data, like the zoom 
 * level and the position of the graph.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class GraphPerspectiveInfo<V extends VisualVertex, E extends VisualEdge<V>> {

	private static final String LAYOUT_TRANSLATE_X = "LAYOUT_TRANSLATE_X";
	private static final String LAYOUT_TRANSLATE_Y = "LAYOUT_TRANSLATE_Y";
	private static final String VIEW_TRANSLATE_X = "VIEW_TRANSLATE_X";
	private static final String VIEW_TRANSLATE_Y = "VIEW_TRANSLATE_Y";

	private static final String VIEW_ZOOM = "VIEW_ZOOM";

	private static final Point INVALID_POINT = null;
	private static final double INVALID_ZOOM = -1D;

	/**
	 * The offset of the transform from the world origin (which at the time of writing is
	 * the (0,0) at the upper left-hand corner of the GUI.  This is for the layout transformer.
	 */
	private final Point layoutTranslateCoordinates;

	/**
	 * The offset of the transform from the world origin (which at the time of writing is
	 * the (0,0) at the upper left-hand corner of the GUI.  This is for the view transformer, 
	 * which also potentially has a scale applied to the transform.
	 */
	private final Point viewTranslateCoordinates;

	private final double zoom;
	private boolean restoreZoom;

	public static <V extends VisualVertex, E extends VisualEdge<V>> GraphPerspectiveInfo<V, E> createInvalidGraphPerspectiveInfo() {
		return new GraphPerspectiveInfo<>();
	}

	private GraphPerspectiveInfo() {
		// for factory construction
		this.zoom = INVALID_ZOOM;
		this.restoreZoom = false;
		this.layoutTranslateCoordinates = null;
		this.viewTranslateCoordinates = null;
	}

	public GraphPerspectiveInfo(RenderContext<V, E> renderContext, double zoom) {
		this.zoom = zoom;
		this.restoreZoom = true;

		MultiLayerTransformer transformer = renderContext.getMultiLayerTransformer();
		double tx = transformer.getTransformer(Layer.LAYOUT).getTranslateX();
		double ty = transformer.getTransformer(Layer.LAYOUT).getTranslateY();
		this.layoutTranslateCoordinates = new Point((int) tx, (int) ty);

		tx = transformer.getTransformer(Layer.VIEW).getTranslateX();
		ty = transformer.getTransformer(Layer.VIEW).getTranslateY();
		this.viewTranslateCoordinates = new Point((int) tx, (int) ty);
	}

	public GraphPerspectiveInfo(SaveState saveState) {
		double savedZoom = saveState.getDouble(VIEW_ZOOM, INVALID_ZOOM);

		int layoutTranslateX = saveState.getInt(LAYOUT_TRANSLATE_X, Integer.MAX_VALUE);
		int layoutTranslateY = saveState.getInt(LAYOUT_TRANSLATE_Y, Integer.MAX_VALUE);
		if (layoutTranslateX == Integer.MAX_VALUE || layoutTranslateY == Integer.MAX_VALUE) {
			layoutTranslateCoordinates = INVALID_POINT;
			viewTranslateCoordinates = INVALID_POINT;
			zoom = INVALID_ZOOM;
			return;
		}

		int viewTranslateX = saveState.getInt(VIEW_TRANSLATE_X, Integer.MAX_VALUE);
		int viewTranslateY = saveState.getInt(VIEW_TRANSLATE_Y, Integer.MAX_VALUE);
		if (viewTranslateX == Integer.MAX_VALUE || viewTranslateY == Integer.MAX_VALUE) {
			layoutTranslateCoordinates = INVALID_POINT;
			viewTranslateCoordinates = INVALID_POINT;
			zoom = INVALID_ZOOM;
			return;
		}

		layoutTranslateCoordinates = new Point(layoutTranslateX, layoutTranslateY);
		viewTranslateCoordinates = new Point(viewTranslateX, viewTranslateY);
		zoom = savedZoom;
		restoreZoom = true; // when we are coming from a persisted state, we restore the zoom
	}

	public void saveState(SaveState saveState) {
		if (isInvalid()) {
			return;
		}

		saveState.putDouble(VIEW_ZOOM, zoom);
		saveState.putInt(LAYOUT_TRANSLATE_X, layoutTranslateCoordinates.x);
		saveState.putInt(LAYOUT_TRANSLATE_Y, layoutTranslateCoordinates.y);
	}

	public boolean isInvalid() {
		return layoutTranslateCoordinates == INVALID_POINT ||
			viewTranslateCoordinates == INVALID_POINT;
	}

	/**
	 * The offset of the transform from the world origin (which at the time of writing is
	 * the (0,0) at the upper left-hand corner of the GUI.  This is for the layout transformer.
	 */
	public Point getLayoutTranslateCoordinates() {
		return layoutTranslateCoordinates;
	}

	/**
	 * The offset of the transform from the world origin (which at the time of writing is
	 * the (0,0) at the upper left-hand corner of the GUI.  This is for the view transformer, 
	 * which also potentially has a scale applied to the transform.
	 */
	public Point getViewTranslateCoordinates() {
		return viewTranslateCoordinates;
	}

	public boolean isRestoreZoom() {
		return restoreZoom;
	}

	public double getZoom() {
		return zoom;
	}

	@Override
	public String toString() {
		// @formatter:off
		return "{\n\tisRestoreZoom: " + restoreZoom +
			",\n\tlayoutTranslateCoordinates: " + layoutTranslateCoordinates +
			",\n\tviewTranslateCoordinates: " + viewTranslateCoordinates +
			",\n\tzoom=" + zoom + 
		"\n}";
		// @formatter:on
	}

}
