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
package ghidra.graph.algo;

import java.util.*;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;

public class TarjanStronglyConnectedAlgorthm<V, E extends GEdge<V>> {
	private GDirectedGraph<V, E> graph;
	private Map<V, TarjanVertexInfo> vertexToInfos = new HashMap<>();
	private Stack<V> stack = new Stack<>();
	private Set<V> set = new HashSet<>();
	private Set<Set<V>> stronglyConnectedList = new HashSet<>();

	public TarjanStronglyConnectedAlgorthm(GDirectedGraph<V, E> g) {
		this.graph = g;
		compute();
	}

	private void compute() {
		for (V v : graph.getVertices()) {
			if (!vertexToInfos.containsKey(v)) {
				strongConnect(v);
			}
		}
	}

	private TarjanVertexInfo strongConnect(V v) {
		TarjanVertexInfo vInfo = new TarjanVertexInfo();
		vertexToInfos.put(v, vInfo);
		push(v);

		for (E edge : graph.getOutEdges(v)) {
			V w = edge.getEnd();
			TarjanVertexInfo wInfo = vertexToInfos.get(w);
			if (wInfo == null) {
				wInfo = strongConnect(w);
				vInfo.lowLink = Math.min(vInfo.lowLink, wInfo.lowLink);
			}
			else if (set.contains(w)) {
				vInfo.lowLink = Math.min(vInfo.lowLink, wInfo.index);
			}
		}

		if (vInfo.lowLink == vInfo.index) {
			Set<V> connectedSet = new HashSet<>();
			connectedSet.add(v);
			for (V w = pop(); v != w; w = pop()) {
				connectedSet.add(w);
			}
			stronglyConnectedList.add(connectedSet);
		}

		return vInfo;
	}

	private void push(V v) {
		stack.push(v);
		set.add(v);
	}

	private V pop() {
		V v = stack.pop();
		set.remove(v);
		return v;
	}

	public Set<Set<V>> getConnectedComponents() {
		return stronglyConnectedList;
	}

	static class TarjanVertexInfo {
		private static int nextIndex = 0;
		public int index;
		public int lowLink;

		public TarjanVertexInfo() {
			index = nextIndex;
			lowLink = index;
			nextIndex++;
		}
	}
}
