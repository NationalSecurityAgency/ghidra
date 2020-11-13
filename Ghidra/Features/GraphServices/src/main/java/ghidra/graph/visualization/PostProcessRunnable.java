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

import java.util.*;

import org.jgrapht.Graph;
import org.jungrapht.visualization.layout.model.LayoutModel;

/**
 * to post-process tree layouts to move vertices that overlap a vertical edge that
 * is not incident on the vertex.
 * This can be removed after jungrapht-layout-1.1
 * @param <V> vertex type
 * @param <E> edge type
 */
public class PostProcessRunnable<V, E> implements Runnable {

	LayoutModel<V> layoutModel;

	public PostProcessRunnable(LayoutModel<V> layoutModel) {
		this.layoutModel = layoutModel;
	}

	@Override
	public void run() {
		moveVerticesThatOverlapVerticalEdges(layoutModel);
	}

	protected int moveVerticesThatOverlapVerticalEdges(LayoutModel<V> layoutModel) {
		int offset = 100;
		int moved = 0;
		Graph<V, E> graph = layoutModel.getGraph();
		Map<Double, Set<E>> verticalEdgeMap = new LinkedHashMap<>();
		graph.edgeSet()
				.stream()
				.filter(e -> layoutModel.apply(graph.getEdgeSource(e)).x == layoutModel
						.apply(graph.getEdgeTarget(e)).x)
				.forEach(e -> verticalEdgeMap
						.computeIfAbsent(layoutModel.apply(graph.getEdgeSource(e)).x,
							k -> new HashSet<>())
						.add(e));

		for (V v : graph.vertexSet()) {
			double x = layoutModel.apply(v).x;
			for (E edge : verticalEdgeMap.getOrDefault(x, Collections.emptySet())) {
				V source = graph.getEdgeSource(edge);
				V target = graph.getEdgeTarget(edge);
				if (!v.equals(source) && !v.equals(target)) {
					double lowy = layoutModel.apply(source).y;
					double hiy = layoutModel.apply(target).y;
					if (lowy > hiy) {
						double temp = lowy;
						lowy = hiy;
						hiy = temp;
					}
					double vy = layoutModel.apply(v).y;
					if (lowy <= vy && vy <= hiy) {
						layoutModel.set(v, layoutModel.apply(v).add(offset, 0));
						moved++;
					}
				}
			}
		}
		return moved;
	}
}
