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
package ghidra.graph.visualization.layout;

import java.util.function.Function;

import org.jgrapht.Graph;
import org.jungrapht.visualization.layout.algorithms.TidierTreeLayoutAlgorithm;
import org.jungrapht.visualization.layout.model.Dimension;
import org.jungrapht.visualization.layout.model.Rectangle;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * Overridden to fix spacing issues on the vertical and horizontal axes.
 */
public class JgtTidierTreeLayoutAlgorithm
		extends TidierTreeLayoutAlgorithm<AttributedVertex, AttributedEdge> {

	@SuppressWarnings("unchecked")
	public static Builder<?, ?> edgeAwareBuilder() {
		return new Builder<>();
	}

	public JgtTidierTreeLayoutAlgorithm(Builder<?, ?> builder) {
		super(builder);

		// when true, excess vertical space sometimes appears that users don't like
		expandLayout = false;
	}

	@Override
	protected <E> Dimension computeAverageVertexDimension(Graph<AttributedVertex, E> graph,
			Function<AttributedVertex, Rectangle> shapeFunction) {

		// The super call uses the average size of the vertices to create spacing.  Large vertices
		// can cause a large amount of space to be used on the x axis. 
		return Dimension.of(50, 50);
	}

	//@formatter:off
	public static class Builder<
		T extends TidierTreeLayoutAlgorithm<AttributedVertex, AttributedEdge>,
		B extends Builder<T, B>>
	
			extends TidierTreeLayoutAlgorithm.Builder<AttributedVertex, AttributedEdge, T, B> {

		@SuppressWarnings("unchecked")
		@Override
		public T build() {
			return (T) new JgtTidierTreeLayoutAlgorithm(this);
		}
	}
	//@formatter:on
}
