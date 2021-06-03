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
package ghidra.graph.viewer.event.mouse;

import java.awt.Point;
import java.awt.Shape;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.control.SatelliteVisualizationViewer;
import ghidra.graph.viewer.*;

public abstract class VisualGraphSatelliteAbstractGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualGraphAbstractGraphMousePlugin<V, E> {

	public VisualGraphSatelliteAbstractGraphMousePlugin() {
		this(InputEvent.BUTTON1_DOWN_MASK);
	}

	public VisualGraphSatelliteAbstractGraphMousePlugin(int selectionModifiers) {
		super(selectionModifiers);
	}

	@Override
	protected boolean shouldShowCursor(MouseEvent e) {
		return false;
	}

	@SuppressWarnings("unchecked")
	protected void moveMasterViewerToMousePoint(MouseEvent e) {

		VisualizationViewer<V, E> satelliteViewer = (VisualizationViewer<V, E>) e.getSource();

		Point pointInLayoutSpace =
			translateSatelliteViewPointToLayoutPoint(satelliteViewer, e.getPoint());
		VisualGraphViewUpdater<V, E> updater = getViewUpdater(e);
		updater.centerLayoutSpacePointWithoutAnimation(pointInLayoutSpace);
	}

	protected boolean isInSatelliteLensArea(MouseEvent e) {
		// must be inside of the 'lens' ...
		VisualizationViewer<V, E> satelliteViewer = getSatelliteGraphViewer(e);
		VisualizationViewer<V, E> viewMaster =
			((SatelliteVisualizationViewer<V, E>) satelliteViewer).getMaster();

		Shape lensInSatelliteViewSpace =
			getSatelliteLensInSatelliteViewSpace(satelliteViewer, viewMaster);
		return lensInSatelliteViewSpace.contains(e.getPoint());
	}

	protected Shape getSatelliteLensInSatelliteViewSpace(VisualizationViewer<V, E> satelliteViewer,
			VisualizationViewer<V, E> viewMaster) {

		RenderContext<V, E> renderContext = viewMaster.getRenderContext();
		MultiLayerTransformer masterMultiLayerTransformer =
			renderContext.getMultiLayerTransformer();

		// translate the shape from master view space to the shared layout space...
		Shape lens = viewMaster.getBounds();
		Shape lensInLayoutSpace = masterMultiLayerTransformer.inverseTransform(lens);

		// ...now translate the shape from the shared layout space to the satellite view space
		MultiLayerTransformer satelliteMultiLayerTransformer =
			satelliteViewer.getRenderContext().getMultiLayerTransformer();
		Shape lenInSatelliteViewSpace = satelliteMultiLayerTransformer.transform(lensInLayoutSpace);
		return lenInSatelliteViewSpace;
	}

	protected Point translateSatelliteViewPointToLayoutPoint(VisualizationViewer<V, E> viewer,
			Point2D point) {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		Point2D layoutPoint2D = multiLayerTransformer.inverseTransform(point);
		int x = (int) layoutPoint2D.getX();
		int y = (int) layoutPoint2D.getY();
		return new Point(x, y);
	}
}
