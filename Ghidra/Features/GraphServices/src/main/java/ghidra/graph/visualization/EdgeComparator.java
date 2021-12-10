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

import java.util.Comparator;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.GraphType;

/**
 * Edge comparator that compares edges based on their edge type. The default renderer will use
 * the order in which the edge types were defined in the {@link GraphType}.
 */
public class EdgeComparator implements Comparator<AttributedEdge> {

	private GraphRenderer renderer;

	public EdgeComparator(GraphRenderer renderer) {
		this.renderer = renderer;
	}

	@Override
	public int compare(AttributedEdge edge1, AttributedEdge edge2) {
		String edgeType1 = edge1.getEdgeType();
		String edgeType2 = edge2.getEdgeType();

		if (edgeType1 == null && edgeType2 == null) {
			return 0;
		}
		if (edgeType1 == null) {
			return 1;
		}
		if (edgeType2 == null) {
			return -1;
		}

		Integer priority1 = renderer.getEdgePriority(edgeType1);
		Integer priority2 = renderer.getEdgePriority(edgeType2);

		return priority1.compareTo(priority2);
	}

}
