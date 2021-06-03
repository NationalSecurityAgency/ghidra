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

import ghidra.service.graph.AttributedEdge;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code Comparator} to order {@code AttributedEdge}s based on their position in a
 * supplied {@code List}.
 *
 */
public class EdgeComparator implements Comparator<AttributedEdge> {

	/**
	 * {@code Map} of EdgeType attribute value to integer priority
	 */
	private Map<String, Integer> edgePriorityMap = new HashMap();

	/**
	 * Create an instance and place the list values into the {@code edgePriorityMap}
	 * with a one-up counter expressing their relative priority
	 * @param edgePriorityList
	 */
	public EdgeComparator(List<String> edgePriorityList) {
		edgePriorityList.forEach(s -> edgePriorityMap.put(s, edgePriorityList.indexOf(s)));
	}

	/**
	 * {@inheritdoc}
	 * Compares the {@code AttributedEdge}s using their priority in the supplied {@code edgePriorityMap}
	 */
	@Override
	public int compare(AttributedEdge edgeOne, AttributedEdge edgeTwo) {
		return priority(edgeOne).compareTo(priority(edgeTwo));
	}

	private Integer priority(AttributedEdge e) {
		return edgePriorityMap.getOrDefault(e.getAttribute("EdgeType"), 0);
	}
}
