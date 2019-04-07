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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.geom.Point2D;
import java.util.*;

import org.jdom.Element;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

public class GroupVertexSerializer {

	private static final String GROUP_VERTICES_ELEMENT_NAME = "GROUP_VERTICES";
	private static final String REGROUP_VERTICES_ELEMENT_NAME = "REGROUP_VERTICES";

	private GroupVertexSerializer() {
		// factory class--no need to instantiate
	}

	public static Element getXMLForRegroupableVertices(FunctionGraph functionGraph) {
		Element element = new Element(REGROUP_VERTICES_ELEMENT_NAME);
		Collection<GroupHistoryInfo> groupHistory = functionGraph.getGroupHistory();
		for (GroupHistoryInfo info : groupHistory) {
			element.addContent(info.toXML(functionGraph));
		}
		return element;
	}

	public static Element getXMLForGroupedVertices(FunctionGraph functionGraph) {
		Element element = new Element(GROUP_VERTICES_ELEMENT_NAME);
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				GroupedVertexInfo info =
					new GroupedVertexInfo((GroupedFunctionGraphVertex) vertex, functionGraph);
				element.addContent(info.toXML());
			}
		}
		return element;
	}

	public static Collection<GroupHistoryInfo> recreateGroupHistory(FGController controller,
			Element element) {

		Set<GroupHistoryInfo> set = new HashSet<>();

		@SuppressWarnings("unchecked")
		List<Element> children = element.getChildren(GroupHistoryInfo.GROUP_HISTORY_ELEMENT_NAME);
		for (Element child : children) {
			set.add(new GroupHistoryInfo(controller, child));
		}

		return set;
	}

	public static void recreateGroupedVertices(FGController controller, Element element) {
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				//
				// Assumption!: At this point in our re-serializing, if we have any group
				// vertices in the graph, then we must assume that the given graph has already
				// been loaded (i.e., it is a cached graph)
				//
				return;
			}
		}

		@SuppressWarnings("unchecked")
		List<Element> children =
			element.getChildren(GroupedVertexInfo.GROUPED_VERTEX_INFO_ELEMENT_NAME);

		Map<AddressHasher, FGVertex> vertexMap = hashVerticesByStartAndEndAddress(functionGraph);
		for (Element groupedVertexElement : children) {
			GroupedVertexInfo info = new GroupedVertexInfo(groupedVertexElement);
			GroupedFunctionGraphVertex vertex =
				(GroupedFunctionGraphVertex) info.getVertex(controller, vertexMap);
			Point2D location = info.getVertexLocation();
			installGroupVertex(controller, vertex, location);
		}
	}

	private static void installGroupVertex(final FGController controller,
			final GroupedFunctionGraphVertex vertex, final Point2D location) {

		if (vertex == null) {
			// can happen when the block model has changed since persisting			
			return;
		}

		controller.installGroupVertex(vertex, location);
	}

	private static Map<AddressHasher, FGVertex> hashVerticesByStartAndEndAddress(
			FunctionGraph functionGraph) {
		Map<AddressHasher, FGVertex> map = new HashMap<>();
		Set<FGVertex> vertices = functionGraph.getUngroupedVertices();
		for (FGVertex vertex : vertices) {
			AddressSetView addresses = vertex.getAddresses();
			Address minAddress = addresses.getMinAddress();
			Address maxAddress = addresses.getMaxAddress();
			map.put(new AddressHasher(minAddress, maxAddress), vertex);
		}
		return map;
	}
}
