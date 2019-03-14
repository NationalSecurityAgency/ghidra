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

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

public class GroupHistoryInfo {

	static final String GROUP_HISTORY_ELEMENT_NAME = "GROUP_HISTORY";
	private static final String GROUP_DESCRIPTION_ATTRIBUTE = "GROUP_DESCRIPTION";

	// TODO may want to keep track of the original grouped vertices (they can change) so that
	// we can reconstitute the original group text so that we can know to updated when later
	// regrouping
	private final Set<FGVertex> groupVertices;
	private String groupDescription;

	private final AddressInfo addressInfo;
	private final PointInfo locationInfo;

	public GroupHistoryInfo(FunctionGraph functionGraph, GroupedFunctionGraphVertex groupVertex) {
		this.groupVertices = new HashSet<>(groupVertex.getVertices());
		if (groupVertices.isEmpty()) {
			throw new IllegalArgumentException(
				"Cannot create a group history entry with no vertices!");
		}

		this.groupDescription = groupVertex.getUserText();

		if (groupDescription == null) {
			throw new IllegalArgumentException("Group description cannot be null");
		}

		Layout<FGVertex, FGEdge> graphLayout = functionGraph.getLayout();
		Point2D location = graphLayout.apply(groupVertex);
		locationInfo = new PointInfo(location);

		addressInfo = new AddressInfo(groupVertex);
	}

	@SuppressWarnings("unchecked")
	public GroupHistoryInfo(FGController controller, Element element) {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Map<AddressHasher, FGVertex> vertexMap = hashVerticesByStartAndEndAddress(functionGraph);

		groupVertices = new HashSet<>();
		List<Element> children = element.getChildren(VertexInfo.VERTEX_INFO_ELEMENT_NAME);
		for (Element vertexInfoElement : children) {
			// NOTE: we use the VertexInfo here to deserialize itself, which it does well
			VertexInfo vertexInfo = new VertexInfo(vertexInfoElement);
			FGVertex vertex = vertexInfo.getVertex(controller, vertexMap);
			if (vertex != null) {
				groupVertices.add(vertex);
			}
			else {
				// Could be null if the structure of the function changes (like during background
				// analysis).  This can also happen if a graph is cloned and the saved settings
				// don't match the current state of the graph.
				Msg.debug(this, "Unable to re-serialize vertex for info: " + vertexInfo);
			}
		}

		children = element.getChildren(GroupedVertexInfo.GROUPED_VERTEX_INFO_ELEMENT_NAME);
		for (Element vertexInfoElement : children) {
			GroupedVertexInfo vertexInfo = new GroupedVertexInfo(vertexInfoElement);
			FGVertex vertex = vertexInfo.locateVertex(controller, vertexMap);
			if (vertex != null) {
				groupVertices.add(vertex);
			}
			else {
				// could be null if the structure of the function changes (not sure when this
				// can happen in reality--there is probably a bug here)
				Msg.debug(this, "Unable to re-serialize vertex for info: " + vertexInfo);
			}
		}

		String escpapedGroupDescription = element.getAttributeValue(GROUP_DESCRIPTION_ATTRIBUTE);
		groupDescription = XmlUtilities.unEscapeElementEntities(escpapedGroupDescription);

		Element vertexInfoElement = element.getChild(AddressInfo.VERTEX_ADDRESS_INFO_ELEMENT_NAME);
		addressInfo = new AddressInfo(vertexInfoElement);

		Element locationElement = element.getChild(VertexInfo.LOCATION_INFO_ELEMENT_NAME);
		Element pointInfoElement = locationElement.getChild(PointInfo.POINT_INFO_ELEMENT_NAME);
		locationInfo = new PointInfo(pointInfoElement);
	}

	/**
	 * Signals that the user has changed the text of a group node and that and this pre-existing
	 * info needs to update.
	 * 
	 * @param text The new text
	 */
	public void setGroupDescription(String text) {
		this.groupDescription = text;
		for (FGVertex vertex : groupVertices) {
			vertex.updateGroupAssociationStatus(this); // the vertices may be caching this info
		}
	}

	public boolean contains(FGVertex vertex) {
		for (FGVertex child : groupVertices) {
			if (matchesOrContains(child, vertex)) {
				return true;
			}
		}
		return false;
	}

	private boolean matchesOrContains(FGVertex potentialMatch, FGVertex vertex) {

		if (potentialMatch.equals(vertex)) {
			return true;
		}

		if (potentialMatch instanceof GroupedFunctionGraphVertex) {
			Set<FGVertex> vertices = ((GroupedFunctionGraphVertex) potentialMatch).getVertices();
			for (FGVertex child : vertices) {
				if (matchesOrContains(child, vertex)) {
					return true;
				}
			}
		}
		return false;
	}

	public void removeVertex(FGVertex vertex) {
		updateGroupDescription(vertex);

		groupVertices.remove(vertex);

		// also fixup any internal groups that may contain the given vertex
		removeFromGroups(vertex);
	}

	private void updateGroupDescription(FGVertex vertex) {
		String text = GroupedFunctionGraphVertex.getVertexDescription(vertex);
		int index = groupDescription.indexOf(text);
		if (index != -1) {
			StringBuffer buffy = new StringBuffer(groupDescription);
			buffy.delete(index, index + text.length());
			groupDescription = buffy.toString();
		}
	}

	private void removeFromGroups(FGVertex oldVertex) {
		// copy, as we may mutate
		Set<FGVertex> vertices = new HashSet<>(groupVertices);

		for (FGVertex vertex : vertices) {
			if (vertex.equals(oldVertex)) {
				groupVertices.remove(oldVertex);
				continue;
			}

			if (!(vertex instanceof GroupedFunctionGraphVertex)) {
				continue;
			}

			GroupedFunctionGraphVertex oldGroup = (GroupedFunctionGraphVertex) vertex;
			GroupedFunctionGraphVertex newGroup = removeFromGroup(oldVertex, oldGroup);
			if (newGroup != null) {
				// the vertex has been removed--update out vertices
				groupVertices.remove(oldGroup);
				groupVertices.add(newGroup);
			}
		}
	}

	private GroupedFunctionGraphVertex removeFromGroup(FGVertex oldVertex,
			GroupedFunctionGraphVertex oldGroup) {
		Set<FGVertex> toRemove = new HashSet<>();

		Set<FGVertex> vertices = oldGroup.getVertices();
		for (FGVertex vertex : vertices) {
			if (vertex.equals(oldVertex)) {
				toRemove.add(vertex);
			}

			if (!(vertex instanceof GroupedFunctionGraphVertex)) {
				continue;
			}

			GroupedFunctionGraphVertex newGroup =
				removeFromGroup(oldVertex, (GroupedFunctionGraphVertex) vertex);

			if (newGroup != null) {
				// the vertex has been removed--update out vertices
				groupVertices.remove(oldGroup);
				groupVertices.add(newGroup);
			}
		}

		return oldGroup.removeAll(toRemove);
	}

	public Point2D getGroupLocation() {
		return locationInfo.getPoint();
	}

	public Set<FGVertex> getVertices() {
		return Collections.unmodifiableSet(groupVertices);
	}

	public String getGroupDescription() {
		return groupDescription;
	}

	public Element toXML(FunctionGraph functionGraph) {
		Element element = new Element(GROUP_HISTORY_ELEMENT_NAME);

		//
		// Grouped vertices content
		//
		for (FGVertex vertex : groupVertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				GroupedVertexInfo vertexInfo =
					new GroupedVertexInfo((GroupedFunctionGraphVertex) vertex, functionGraph);
				element.addContent(vertexInfo.toXML());
			}
			else {
				VertexInfo vertexInfo = new VertexInfo(vertex, functionGraph);
				element.addContent(vertexInfo.toXML());
			}
		}

		//
		// Group description
		//
		String escapedText = XmlUtilities.escapeElementEntities(groupDescription);
		element.setAttribute(GROUP_DESCRIPTION_ATTRIBUTE, escapedText);

		//
		// Group vertex address
		//
		addressInfo.write(element);

		//
		// Group location
		//
		Element locationElement = new Element(VertexInfo.LOCATION_INFO_ELEMENT_NAME);
		locationInfo.write(locationElement);
		element.addContent(locationElement);

		return element;
	}

	@Override
	public String toString() {
		return "text=\"" + groupDescription + "\", AddressInfo=" + addressInfo + ", location=" +
			locationInfo;
	}

	private static Map<AddressHasher, FGVertex> hashVerticesByStartAndEndAddress(
			FunctionGraph functionGraph) {
		Map<AddressHasher, FGVertex> map = new HashMap<>();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();

		for (FGVertex vertex : vertices) {
			AddressSetView addresses = vertex.getAddresses();
			Address minAddress = addresses.getMinAddress();
			Address maxAddress = addresses.getMaxAddress();
			map.put(new AddressHasher(minAddress, maxAddress), vertex);
		}
		return map;
	}
}
