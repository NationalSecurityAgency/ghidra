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

import static util.CollectionUtils.*;

import java.util.Iterator;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.google.common.collect.Iterators;
import com.google.common.collect.UnmodifiableIterator;

import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.*;

/**
 * Uses the given filter to fade out vertices that do not pass.  Vertices that pass the filter
 * will be included in the graph.  Not only will passing vertices be included, but so too 
 * will any vertices reachable from those vertices.
 * 
 * <P>This job will update the graph so that any previously filtered vertices will be put
 * back into the graph.   
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class FilterVerticesJob<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractGraphVisibilityTransitionJob<V, E> {

	/** The minimum threshold for visibility when fading out */
	private static final double MIN_ALPHA = 0.2;

	// false will leave the vertices faded out, but not removed from the graph
	private boolean removeVertices;
	private FilteringVisualGraph<V, E> filterGraph;

	private Set<V> passedVertices;
	private Set<V> failedVertices;
	private Set<E> failedEdges;
	private Set<E> passedEdges;

	private Predicate<V> filter;

	/**
	 * Constructor
	 * 
	 * @param viewer the viewer upon which to operate
	 * @param graph the graph to filter
	 * @param filter the predicate used to determine what passes the filter
	 * @param remove true signals to remove the vertices from the view; false signals to leave
	 *               them visible, but faded to show that they failed the filter
	 */
	public FilterVerticesJob(GraphViewer<V, E> viewer, FilteringVisualGraph<V, E> graph,
			Predicate<V> filter, boolean remove) {
		super(viewer, true);
		this.filter = filter;
		this.removeVertices = remove;
		this.filterGraph = graph;

		// Note: we cannot initialize here due to the fact that another job may be running
		//       when this job is created.  That job will be making changes to the graph after
		//       this constructor is called, which could invalidate work done at this point.
	}

	@Override
	void start() {
		initialize();
		super.start();
	}

	private void initialize() {

		//
		// Basic Algorithm
		// 1) Filter the entire universe of vertices/edges
		// 2) Get current vertices/edges that need to be removed (this happens by simply
		//    not restoring those vertices/edges that are already filtered)
		// 3) Restore any filtered vertices that now pass the filter 
		//

		// 1)
		//@formatter:off
		Iterator<V> vertices = filterGraph.getAllVertices();
		Set<V> matching = asStream(vertices)			
			.filter(filter)
			.collect(Collectors.toSet())
	        ;
		//@formatter:on

		Set<V> related = filterGraph.getAllReachableVertices(matching);
		matching.addAll(related);
		passedVertices = matching;

		// 2)
		failedVertices = findCurrentVerticesFailingTheFilter(matching);
		failedEdges = filterGraph.getAllEdges(failedVertices);

		Set<E> allRelatedEdges = filterGraph.getAllEdges(passedVertices);
		allRelatedEdges.removeAll(failedEdges);
		passedEdges = allRelatedEdges;

		// 3)
		filterGraph.unfilterVertices(passedVertices);
	}

	private Set<V> findCurrentVerticesFailingTheFilter(Set<V> validVertices) {

		UnmodifiableIterator<V> nonMatchingIterator =
			Iterators.filter(filterGraph.getUnfilteredVertices(), v -> !validVertices.contains(v));
		Set<V> nonMatching = asSet(nonMatchingIterator);
		return nonMatching;
	}

	/*
	 * This is the callback from the animator, with values that range from 0.0 to 1.0.
	 */
	@Override
	protected void updateOpacity(double percentComplete) {

		//
		// Fade Out will start with the current alpha, bringing the value down to the minimum.
		// This will only have an effect if the current alpha is not already at the minimum, 
		// such as from a previous filter.
		//
		double percentRemaining = 1.0 - percentComplete;
		double fadeOutAlpha = Math.max(percentRemaining, getMinimumAlpha());

		failedVertices.forEach(v -> fadeOutAlpha(v, fadeOutAlpha));
		failedEdges.forEach(e -> fadeOutAlpha(e, fadeOutAlpha));

		//
		// Fade In will start with the current alpha, bringing the value up to 1.0.  This will
		// only have an effect if the current alpha is not already 1.0, such as from a 
		// previous filter.
		//
		double fadeInAlpha = percentComplete;
		passedVertices.forEach(v -> fadeInAlpha(v, fadeInAlpha));
		passedEdges.forEach(e -> fadeInAlpha(e, fadeInAlpha));

	}

	private double getMinimumAlpha() {
		return removeVertices ? 0D : MIN_ALPHA;
	}

	private void fadeOutAlpha(V v, double fadeOutAlpha) {

		// keep the old alpha if it is already faded out
		double alpha = v.getAlpha();
		double newAlpha = Math.min(alpha, fadeOutAlpha);
		v.setAlpha(newAlpha);
	}

	private void fadeOutAlpha(E e, double fadeOutAlpha) {

		// keep the old alpha if it is already faded out
		double alpha = e.getAlpha();
		double newAlpha = Math.min(alpha, fadeOutAlpha);
		e.setAlpha(newAlpha);
	}

	private void fadeInAlpha(V v, double fadeInAlpha) {

		// keep the new alpha if it is already faded in
		double alpha = v.getAlpha();
		double newAlpha = Math.max(alpha, fadeInAlpha);
		v.setAlpha(newAlpha);
	}

	private void fadeInAlpha(E e, double fadeInAlpha) {

		// keep the new alpha if it is already faded in
		double alpha = e.getAlpha();
		double newAlpha = Math.max(alpha, fadeInAlpha);
		e.setAlpha(newAlpha);
	}

	@Override
	protected void finished() {

		// We know that init() will setup our vertices to filter.  If they are null, then 
		// init() wasn't called, because start() was never called.
		if (passedVertices == null) {
			initialize();
		}

		super.finished();

		if (removeVertices) {
			filterGraph.filterVertices(failedVertices);
		}
	}
}
