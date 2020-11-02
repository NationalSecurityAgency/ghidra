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

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import javax.swing.SwingUtilities;

import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.control.SatelliteVisualizationViewer;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

public class VisualGraphSatelliteTranslatingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualGraphSatelliteAbstractGraphMousePlugin<V, E> {

	private boolean didDrag;

	// Note: for ideas on resizing instead of moving, see LensTranslatingGraphMousePlugin     
	public VisualGraphSatelliteTranslatingGraphMousePlugin() {
		super(InputEvent.BUTTON1_DOWN_MASK);
		this.cursor = Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR);
	}

	// our cursor is shown when we are over our little lens that represents the master view
	@Override
	protected boolean shouldShowCursor(MouseEvent e) {
		return isInSatelliteLensArea(e);
	}

	@Override
	@SuppressWarnings("unchecked")
	public void mouseDragged(MouseEvent e) {
		if (!checkModifiers(e)) {
			return;
		}

		if (!isHandlingMouseEvents) {
			return;
		}

		didDrag = true;
		e.consume();

		VisualizationViewer<V, E> satelliteViewer = (VisualizationViewer<V, E>) e.getSource();
		VisualizationViewer<V, E> viewMaster =
			((SatelliteVisualizationViewer<V, E>) satelliteViewer).getMaster();
		MutableTransformer modelTransformerMaster =
			viewMaster.getRenderContext().getMultiLayerTransformer().getTransformer(Layer.LAYOUT);

		Point2D transformedPoint =
			getDeltaForViewSpacePointsInLayoutSpace(e.getPoint(), down, satelliteViewer);
		down = e.getPoint(); // record for future translations

		modelTransformerMaster.translate(transformedPoint.getX(), transformedPoint.getY());
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		if (isHandlingMouseEvents) {
			e.consume();
		}

		if (isInSatelliteLensArea(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	// if we get a click, then the user didn't drag...in this case, just move 
	// (center) the window to the click point
	@Override
	public void mouseClicked(MouseEvent e) {
		if (!isHandlingMouseEvents) {
			return;
		}

		e.consume();
		resetState();
		moveMasterViewerToMousePoint(e);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (!checkModifiers(e)) {
			return;
		}

		if (!isInSatelliteLensArea(e)) {
			return;
		}

		isHandlingMouseEvents = true;
		down = e.getPoint();
		e.consume();
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		if (!isHandlingMouseEvents) {
			return;
		}

		if (!didDrag) {
			// this is the case where we are handling the event, but we didn't drag, which means
			// we will later get a mouseClicked() callback, which we want to do some stuff, so 
			// don't consume the events
			return;
		}

		e.consume();
		resetState();
		didDrag = false;
		down = null;

		VisualizationViewer<V, E> satelliteViewer = getSatelliteGraphViewer(e);
		VisualizationViewer<V, E> viewMaster = getGraphViewer(e);
		Shape satelliteLens = getSatelliteLensInSatelliteViewSpace(satelliteViewer, viewMaster);

		// See if the new mouse point will still allow the lens to fit entirely in the 
		// satellite view.  If not, then we do not want to let the user drag the lens.  Otherwise, 
		// have at it!
		Point adjustedLensPointInViewSpace =
			getLensPointAdjustedForSatelliteBounds(satelliteViewer, satelliteLens);
		Rectangle lensBounds = satelliteLens.getBounds();
		Point currentLensPointInViewSpace = lensBounds.getLocation();

		if (!shouldAdjustLensPoint(currentLensPointInViewSpace, adjustedLensPointInViewSpace,
			lensBounds.getSize())) {
			return;
		}

		Point2D transformedPoint = getDeltaForViewSpacePointsInLayoutSpace(
			adjustedLensPointInViewSpace, currentLensPointInViewSpace, satelliteViewer);
		MutableTransformer modelTransformerMaster =
			viewMaster.getRenderContext().getMultiLayerTransformer().getTransformer(Layer.LAYOUT);
		modelTransformerMaster.translate(transformedPoint.getX(), transformedPoint.getY());
	}

	// if the lens point is off the screen or mostly off the screen, then we should adjust
	private boolean shouldAdjustLensPoint(Point currentLensPoint, Point adjustedLensPoint,
			Dimension size) {
		if (adjustedLensPoint.equals(currentLensPoint)) {
			return false; // no adjustments needed; lens is completely on the satellite
		}

		int x1 = currentLensPoint.x;
		int x2 = adjustedLensPoint.x;
		int xDifference = Math.max(x1, x2) - Math.min(x1, x2);
		if (xDifference > (size.width * .66)) {
			return true;
		}

		int y1 = currentLensPoint.y;
		int y2 = adjustedLensPoint.y;
		int yDifference = Math.max(y1, y2) - Math.min(y1, y2);
		return yDifference > (size.height * .66);
	}

	private Point getLensPointAdjustedForSatelliteBounds(VisualizationViewer<V, E> satelliteViewer,
			Shape satelliteLens) {
		Rectangle bounds = satelliteLens.getBounds();
		Point location = bounds.getLocation();
		location =
			SwingUtilities.convertPoint(satelliteViewer, location, satelliteViewer.getParent());
		bounds.setLocation(location);

		Shape satelliteBounds = satelliteViewer.getBounds();
		Rectangle lensBounds =
			moveRectangleCompletelyOntoOtherRectangle(bounds, satelliteBounds.getBounds());

		Point lensPointRelativeToSatellite = SwingUtilities.convertPoint(
			satelliteViewer.getParent(), lensBounds.getLocation(), satelliteViewer);
		return lensPointRelativeToSatellite;
	}

	private Rectangle moveRectangleCompletelyOntoOtherRectangle(Rectangle moveeRectangle,
			Rectangle destinationRectangle) {

		Rectangle newRectangle = new Rectangle(moveeRectangle);

		newRectangle.x = Math.min(newRectangle.x,
			destinationRectangle.x + destinationRectangle.width - newRectangle.width - 1);
		newRectangle.x = Math.max(newRectangle.x, destinationRectangle.x + 1);
		newRectangle.y = Math.min(newRectangle.y,
			destinationRectangle.y + destinationRectangle.height - newRectangle.height - 1);
		newRectangle.y = Math.max(newRectangle.y, destinationRectangle.y + 1);

		return newRectangle;
	}

	private Point2D getDeltaForViewSpacePointsInLayoutSpace(Point2D newPointInViewSpace,
			Point2D currentPointInViewSpace, VisualizationViewer<V, E> viewer) {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		Point2D currentPointInLayoutSpace =
			multiLayerTransformer.inverseTransform(currentPointInViewSpace);
		Point2D newPointInLayoutSpace = multiLayerTransformer.inverseTransform(newPointInViewSpace);
		float dx = (float) (currentPointInLayoutSpace.getX() - newPointInLayoutSpace.getX());
		float dy = (float) (currentPointInLayoutSpace.getY() - newPointInLayoutSpace.getY());
		return new Point2D.Double(dx, dy);
	}
}
