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
package ghidra.graph.visualization.mouse;

import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;

import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.GraphElementAccessor;
import org.jungrapht.visualization.control.TransformSupport;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.selection.ShapePickSupport;

import static org.jungrapht.visualization.layout.util.PropertyLoader.PREFIX;

/**
 * Keeper of shared logic for jungrapht handling
 */
public class JgtUtils {

	private static final String PICK_AREA_SIZE_PROPERTY = PREFIX + "pickAreaSize";

	/**
	 * Returns the edge under the given mouse event
	 * 
	 * @param <V> the vertex type
	 * @param <E> the edge type
	 * @param e the event
	 * @param viewer the graph viewer
	 * @return the edge
	 */
	public static <V, E> E getEdge(MouseEvent e, VisualizationViewer<V, E> viewer) {
		if (e == null) {
			return null;
		}

		Rectangle2D footprintRectangle = getFootprint(e);
		LayoutModel<V> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (pickSupport == null) {
			return null;
		}

		if (pickSupport instanceof ShapePickSupport) {
			ShapePickSupport<V, E> shapePickSupport =
				(ShapePickSupport<V, E>) pickSupport;
			return shapePickSupport.getEdge(layoutModel, footprintRectangle);
		}

		TransformSupport<V, E> transformSupport =
			viewer.getTransformSupport();
		Point2D layoutPoint = transformSupport.inverseTransform(viewer, e.getPoint());
		return pickSupport.getEdge(layoutModel, layoutPoint.getX(), layoutPoint.getY());
	}

	/**
	 * Returns the vertex under the given mouse event
	 * 
	 * @param <V> the vertex type
	 * @param <E> the edge type
	 * @param e the event
	 * @param viewer the graph viewer
	 * @return the vertex
	 */
	public static <V, E> V getVertex(MouseEvent e, VisualizationViewer<V, E> viewer) {
		if (e == null) {
			return null;
		}

		Rectangle2D footprintRectangle = getFootprint(e);
		LayoutModel<V> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
		if (pickSupport == null) {
			return null;
		}

		if (pickSupport instanceof ShapePickSupport) {
			ShapePickSupport<V, E> shapePickSupport =
				(ShapePickSupport<V, E>) pickSupport;
			return shapePickSupport.getVertex(layoutModel, footprintRectangle);
		}

		TransformSupport<V, E> transformSupport =
			viewer.getTransformSupport();
		Point2D layoutPoint = transformSupport.inverseTransform(viewer, e.getPoint());
		return pickSupport.getVertex(layoutModel, layoutPoint.getX(), layoutPoint.getY());
	}

	private static Rectangle2D getFootprint(MouseEvent e) {
		int pickSize = Integer.getInteger(PICK_AREA_SIZE_PROPERTY, 4);
		return new Rectangle2D.Float(
			e.getPoint().x - pickSize / 2f,
			e.getPoint().y - pickSize / 2f,
			pickSize,
			pickSize);
	}

}
