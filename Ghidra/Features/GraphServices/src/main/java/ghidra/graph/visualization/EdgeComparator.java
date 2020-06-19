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
import java.util.stream.Collectors;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;

public class EdgeComparator implements Comparator<AttributedEdge> {
	private Set<AttributedEdge> prioritized;

	public EdgeComparator(AttributedGraph graph, String attributeName, String value) {
		prioritized = graph.edgeSet()
				.stream()
				.filter(e -> Objects.equals(e.getAttribute(attributeName), value))
				.collect(Collectors.toSet());
	}

	@Override
	public int compare(AttributedEdge edgeOne, AttributedEdge edgeTwo) {
		boolean edgeOnePriority = prioritized.contains(edgeOne);
		boolean edgeTwoPriority = prioritized.contains(edgeTwo);
		if (edgeOnePriority && !edgeTwoPriority) {
			return -1;
		}
		else if (!edgeOnePriority && edgeTwoPriority) {
			return 1;
		}
		return 0;
	}

}
