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
package ghidra.graph.visualization;

import static org.jungrapht.visualization.VisualizationServer.*;

import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;

import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.*;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.selection.ShapePickSupport;

import docking.ComponentProvider;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * An extension of the jungrapht DefaultGraphMouse. This class has references to
 * <ul>
 * <li>a {@link VisualizationViewer} (to access the Graph and LayoutModel)
 *
 */
public class GhidraGraphMouse extends DefaultGraphMouse<AttributedVertex, AttributedEdge> {

	private static final String PICK_AREA_SIZE_PROPERTY = PREFIX + "pickAreaSize";

	private VisualizationViewer<AttributedVertex, AttributedEdge> viewer;

	private int pickSize;

	/**
	 * create an instance with default values
	 * @param componentProvider the graph component provider
	 * @param viewer the graph viewer component
	 */
	GhidraGraphMouse(ComponentProvider componentProvider,
			VisualizationViewer<AttributedVertex, AttributedEdge> viewer) {

		super(DefaultGraphMouse.<AttributedVertex, AttributedEdge> builder());
		this.viewer = viewer;
		pickSize = Integer.getInteger(GhidraGraphMouse.PICK_AREA_SIZE_PROPERTY, 4);
	}

	private Rectangle2D getFootprint(MouseEvent e) {
		return new Rectangle2D.Float(
			e.getPoint().x - pickSize / 2f,
			e.getPoint().y - pickSize / 2f,
			pickSize,
			pickSize);
	}

	AttributedEdge getPickedEdge(MouseEvent e) {
		if (e == null) {
			return null;
		}
		Rectangle2D footprintRectangle = getFootprint(e);
		LayoutModel<AttributedVertex> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		GraphElementAccessor<AttributedVertex, AttributedEdge> pickSupport =
			viewer.getPickSupport();
		if (pickSupport instanceof ShapePickSupport) {
			ShapePickSupport<AttributedVertex, AttributedEdge> shapePickSupport =
				(ShapePickSupport<AttributedVertex, AttributedEdge>) pickSupport;
			return shapePickSupport.getEdge(layoutModel, footprintRectangle);
		}

		TransformSupport<AttributedVertex, AttributedEdge> transformSupport =
			viewer.getTransformSupport();
		Point2D layoutPoint = transformSupport.inverseTransform(viewer, e.getPoint());
		return pickSupport.getEdge(layoutModel, layoutPoint.getX(), layoutPoint.getY());
	}

	AttributedVertex getPickedVertex(MouseEvent e) {
		if (e == null) {
			return null;
		}
		Rectangle2D footprintRectangle = getFootprint(e);
		LayoutModel<AttributedVertex> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		GraphElementAccessor<AttributedVertex, AttributedEdge> pickSupport =
			viewer.getPickSupport();
		if (pickSupport instanceof ShapePickSupport) {
			ShapePickSupport<AttributedVertex, AttributedEdge> shapePickSupport =
				(ShapePickSupport<AttributedVertex, AttributedEdge>) pickSupport;
			return shapePickSupport.getVertex(layoutModel, footprintRectangle);
		}

		TransformSupport<AttributedVertex, AttributedEdge> transformSupport =
			viewer.getTransformSupport();
		Point2D layoutPoint = transformSupport.inverseTransform(viewer, e.getPoint());
		return pickSupport.getVertex(layoutModel, layoutPoint.getX(), layoutPoint.getY());
	}

}
