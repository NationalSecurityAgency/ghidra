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
package ghidra.graph.job;

import java.awt.Point;
import java.awt.geom.Point2D;

import edu.uci.ics.jung.visualization.*;
import ghidra.graph.viewer.*;

public class RelayoutAndCenterVertexGraphJob<V extends VisualVertex, E extends VisualEdge<V>>
		extends RelayoutFunctionGraphJob<V, E> {
	private V vertex;
	private Point2D destination;
	private Point2D lastPoint = new Point2D.Double(0, 0);

	public RelayoutAndCenterVertexGraphJob(GraphViewer<V, E> viewer, V vertex,
			boolean useAnimation) {
		super(viewer, useAnimation);
		this.vertex = vertex;
	}

	@Override
	protected void initializeVertexLocations() {
		super.initializeVertexLocations();
		TransitionPoints transitionPoints = vertexLocations.get(vertex);
		Point2D centerPoint = transitionPoints.destinationPoint;
		Point p = new Point((int) centerPoint.getX(), (int) centerPoint.getY());
		destination = GraphViewerUtils.getOffsetFromCenterInLayoutSpace(viewer, p);
	}

	@Override
	public void setPercentComplete(double percentComplete) {
		super.setPercentComplete(percentComplete);

		double finalX = destination.getX();
		double finalY = destination.getY();

		double lastX = lastPoint.getX();
		double lastY = lastPoint.getY();
		double deltaX = (percentComplete * finalX) - lastX;
		double deltaY = (percentComplete * finalY) - lastY;

		lastPoint.setLocation(lastX + deltaX, lastY + deltaY);

		if (deltaX == 0 && deltaY == 0) {
			return;
		}

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer xform = renderContext.getMultiLayerTransformer();
		xform.getTransformer(Layer.LAYOUT).translate(deltaX, deltaY);
		viewer.repaint();

	}

	@Override
	protected void finished() {
		if (isShortcut) {
			destination = GraphViewerUtils.getVertexOffsetFromLayoutCenter(viewer, vertex);
		}
		super.finished();
	}

}
