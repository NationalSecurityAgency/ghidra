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

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.Animator.RepeatBehavior;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import edu.uci.ics.jung.visualization.VisualizationServer;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A class to animate a vertex in order to draw attention to it.
 * 
 * Note: this class is not a {@link AbstractAnimatorJob} so that it can run concurrently 
 * with jobs in the graph (jobs run one-at-a-time).
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class TwinkleVertexAnimator<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractAnimator {

	private final VisualizationServer<V, E> viewer;
	private final V vertex;
	private final boolean useAnimation;
	private double startEmphasis;

	public TwinkleVertexAnimator(VisualizationServer<V, E> viewer, V vertex, boolean useAnimation) {
		this.viewer = viewer;
		this.vertex = vertex;
		this.useAnimation = useAnimation;
	}

	@Override
	protected Animator createAnimator() {
		if (!useAnimation) {
			return null;
		}

		startEmphasis = vertex.getEmphasis();

		Animator newAnimator = PropertySetter.createAnimator(500, this, "currentEmphasis", 0.0, .5);
		newAnimator.setAcceleration(0.0f);
		newAnimator.setDeceleration(0.0f);
		newAnimator.setRepeatCount(4); // up and down twice
		newAnimator.setRepeatBehavior(RepeatBehavior.REVERSE); // emphasize the first pass, then de-emphasizes
		return newAnimator;
	}

	@Override
	protected void finished() {
		vertex.setEmphasis(startEmphasis);
	}

	public void setCurrentEmphasis(double currentEmphasis) {
		vertex.setEmphasis(currentEmphasis);
		viewer.repaint();
	}

	public V getVertex() {
		return vertex;
	}
}
