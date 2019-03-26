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

import java.awt.geom.Point2D;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import edu.uci.ics.jung.visualization.*;

public abstract class MoveViewAnimatorFunctionGraphJob<V, E>
		extends AbstractAnimatorJob {

	private static final int PIXELS_PER_SECOND = 750;
	private static final int FRAME_PER_SECOND = 10;

	private final Point2D lastPoint = new Point2D.Double();
	private int totalFrames;

	protected final VisualizationViewer<V, E> viewer;
	private MultiLayerTransformer multiLayerTransformer;
	private final boolean useAnimation;
	private Point2D destination;

	public MoveViewAnimatorFunctionGraphJob(VisualizationServer<V, E> viewer,
			boolean useAnimation) {

		if (!(viewer instanceof VisualizationViewer)) {
			throw new IllegalArgumentException("VisualizationServer is not an instance of " +
				"VisualizationViewer.  We currently need this for bounds information.");
		}

		this.viewer = (VisualizationViewer<V, E>) viewer;
		this.useAnimation = useAnimation;
	}

	protected abstract Point2D createDestination();

	@Override
	protected Animator createAnimator() {
		destination = createDestination();

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		multiLayerTransformer = renderContext.getMultiLayerTransformer();

		if (!useAnimation) {
			return null;
		}

		double offsetX = destination.getX();
		double offsetY = destination.getY();
		double durationX = Math.abs(offsetX / PIXELS_PER_SECOND);
		double durationY = Math.abs(offsetY / PIXELS_PER_SECOND);

		int totalFramesX = (int) (durationX * FRAME_PER_SECOND);
		int totalFramesY = (int) (durationY * FRAME_PER_SECOND);

		int mostFrames = Math.max(totalFramesX, totalFramesY);
		mostFrames = Math.min(mostFrames, 15); // limit the time to something reasonable
		totalFrames = Math.max(1, mostFrames); // at least one frame

		double timeInSeconds = (double) totalFrames / (double) FRAME_PER_SECOND;
		int duration = (int) Math.round(timeInSeconds * 1000); // put into millis
		
		Point2D start = new Point2D.Double();
		Animator newAnimator =
			PropertySetter.createAnimator(duration, this, "offset", start, destination);
		newAnimator.setAcceleration(0.2f);
		newAnimator.setDeceleration(0.8f);

		return newAnimator;
	}

	@Override
	protected void finished() {
		if (isShortcut) {
			destination = createDestination();
		}
		setOffset(destination);
	}

	public void setOffset(Point2D offsetFromOriginalPoint) {
		// calculate how far the given offset is from the final destination
		double newX = offsetFromOriginalPoint.getX();
		double newY = offsetFromOriginalPoint.getY();

		double deltaX = newX - lastPoint.getX();
		double deltaY = newY - lastPoint.getY();

		lastPoint.setLocation(newX, newY);

		if (deltaX == 0 && deltaY == 0) {
			return;
		}

		multiLayerTransformer.getTransformer(Layer.LAYOUT).translate(deltaX, deltaY);
		viewer.repaint();
	}
}
