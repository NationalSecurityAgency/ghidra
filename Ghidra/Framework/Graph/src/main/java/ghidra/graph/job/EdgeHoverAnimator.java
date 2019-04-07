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

import java.util.function.Supplier;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import edu.uci.ics.jung.visualization.VisualizationServer;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.renderers.Renderer.Edge;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;

public class EdgeHoverAnimator<V, E> extends AbstractAnimator {

	private static final int MOTION_SPEED = 2000;
	private static final Supplier<Float> ANIMATED_DASHED_LINE_FLOAT_GIVER = () -> {
		long currentTimeMillis = System.currentTimeMillis();
		return (MOTION_SPEED - (currentTimeMillis % MOTION_SPEED)) / (float) MOTION_SPEED;
	};

	private static final int SLEEP_AMOUNT_MILLISECONDS = 300;
	private static final int DURATION = 5000;
	private long lastPaintTime = System.nanoTime();

	private final VisualizationServer<V, E> primaryViewer;
	private final VisualizationServer<V, E> satelliteViewer;

	private final boolean useAnimation;

	public EdgeHoverAnimator(VisualizationServer<V, E> primaryViewer,
			VisualizationServer<V, E> satelliteViewer, boolean useAnimation) {
		this.primaryViewer = primaryViewer;
		this.satelliteViewer = satelliteViewer;
		this.useAnimation = useAnimation;
	}

	@Override
	protected Animator createAnimator() {
		if (!useAnimation) {
			return null;
		}

		Animator newAnimator =
			PropertySetter.createAnimator(DURATION, this, "nextPaint", 0, DURATION);
		newAnimator.setAcceleration(0.0f);
		newAnimator.setDeceleration(0.8f);
		return newAnimator;
	}

	@Override
	protected void finished() {
		paintDashedLineOnce();
	}

	public void setNextPaint(int nextPaint) {
		long currentTime = System.nanoTime();
		long ellapsedMilliseconds = (currentTime - lastPaintTime) / 1000000;
		if (ellapsedMilliseconds > SLEEP_AMOUNT_MILLISECONDS) {
			lastPaintTime = currentTime;
			paintDashedLineOnce();
		}
	}

	private void paintDashedLineOnce() {
		float newPaintOffset = ANIMATED_DASHED_LINE_FLOAT_GIVER.get();
		updateRendererPaintOffset(primaryViewer, newPaintOffset);
		updateRendererPaintOffset(satelliteViewer, newPaintOffset);

		primaryViewer.repaint();
		satelliteViewer.repaint();
	}

	private void updateRendererPaintOffset(VisualizationServer<V, E> viewer, float newPaintOffset) {
		Renderer<V, E> renderer = viewer.getRenderer();
		Edge<V, E> edgeRenderer = renderer.getEdgeRenderer();
		if (!(edgeRenderer instanceof VisualEdgeRenderer)) {
			return; // something is wrong here!
		}
		VisualEdgeRenderer<?, ?> functionGraphEdgeRenderer =
			(VisualEdgeRenderer<?, ?>) edgeRenderer;
		functionGraphEdgeRenderer.setDashingPatternOffset(newPaintOffset);
	}
}
