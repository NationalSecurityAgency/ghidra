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

import static util.CollectionUtils.nonNull;

import java.util.*;
import java.util.stream.Collectors;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.*;

/**
 * A job that provides an animator and callbacks for transitioning the visibility of 
 * graph vertices.  The opacity value will change from 0 to 1 over the course of the job. 
 * Subclasses can decide how to use the opacity value as it changes.   For example, a 
 * subclass can fade in or out the vertices provided to the job.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public abstract class AbstractGraphVisibilityTransitionJob<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractAnimatorJob {

	protected static final int NORMAL_DURATION = 1500;
	protected static final int FAST_DURATION = 700;
	protected int duration = NORMAL_DURATION;

	protected final GraphViewer<V, E> viewer;
	protected final VisualGraph<V, E> graph;

	protected boolean useAnimation;

	protected AbstractGraphVisibilityTransitionJob(GraphViewer<V, E> viewer, boolean useAnimation) {

		this.useAnimation = useAnimation;

		this.viewer = viewer;
		this.graph = viewer.getVisualGraph();

		// don't animate if we have too many vertices in the graph
		if (isTooBigToAnimate()) {
			this.useAnimation = false;
		}
	}

	/**
	 * Returns true if the graph is too large for animation (usually due to performance issues).
	 * 
	 * @return true if the graph is too large for animation
	 */
	protected boolean isTooBigToAnimate() {
		return graph.getVertexCount() >= TOO_BIG_TO_ANIMATE;
	}

	/**
	 * Callback from our animator.
	 */
	public void setPercentComplete(double percentComplete) {
		trace("setPercentComplete() callback: " + percentComplete);
		updateOpacity(percentComplete);
		viewer.repaint();
	}

	@Override
	protected Animator createAnimator() {

		if (!useAnimation) {
			return null;
		}

		updateOpacity(0);

		Animator newAnimator =
			PropertySetter.createAnimator(duration, this, "percentComplete", 0.0, 1.0);
		newAnimator.setAcceleration(0f);
		newAnimator.setDeceleration(0.8f);

		return newAnimator;
	}

	@Override
	protected void finished() {

		setPercentComplete(1D);
		viewer.repaint();
	}

	protected void updateOpacity(double percentComplete) {
		// By default we don't change opacity for just moving vertices around. Some children
		// may be modifying the graph and they can use this callback to change opacity as the
		// job progresses.
	}

	protected Set<E> getEdges(Collection<V> vertices) {

		//@formatter:off
		return vertices
			.stream()
			.map(v -> nonNull(graph.getIncidentEdges(v)))
			.flatMap(collection -> collection.stream())
			.collect(Collectors.toSet())
			;
		//@formatter:on
	}

	protected Collection<E> getEdges(V vertex) {
		List<E> edges = new LinkedList<>();
		Collection<E> inEdges = nonNull(graph.getInEdges(vertex));
		edges.addAll(inEdges);

		Collection<E> outEdges = nonNull(graph.getOutEdges(vertex));
		edges.addAll(outEdges);

		return edges;
	}

}
