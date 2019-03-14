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
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;

/**
 * A class to record vertex information that can be used to find vertex instances in memory.  This
 * facilitates serialization and persistence.
 */
class VertexInfo {

	static final String VERTEX_INFO_ELEMENT_NAME = "VERTEX_INFO";
	static final String LOCATION_INFO_ELEMENT_NAME = "LOCATION_POINT_INFO";

	protected final AddressInfo vertexAddressInfo;
	private final PointInfo locationInfo;

	VertexInfo(FGVertex vertex, FunctionGraph functionGraph) {

		vertexAddressInfo = new AddressInfo(vertex);

		Layout<FGVertex, FGEdge> graphLayout = functionGraph.getLayout();
		Point2D location = graphLayout.apply(vertex);
		locationInfo = new PointInfo(location);
	}

	VertexInfo(Element element) {
		Element vertexInfoElement = element.getChild(AddressInfo.VERTEX_ADDRESS_INFO_ELEMENT_NAME);
		vertexAddressInfo = new AddressInfo(vertexInfoElement);

		Element locationElement = element.getChild(LOCATION_INFO_ELEMENT_NAME);
		Element pointInfoElement = locationElement.getChild(PointInfo.POINT_INFO_ELEMENT_NAME);
		locationInfo = new PointInfo(pointInfoElement);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[AddressInfo=" + vertexAddressInfo + ", location=" +
			locationInfo + "]";
	}

	/**
	 * Finds an existing vertex represented by this info.  Returns null if no vertex exists to 
	 * match this info (this can happen if the code block structure has changed).
	 * 
	 * @param controller The controller used for the current function graph
	 * @return an existing vertex represented by this info.  Returns null if no vertex exists to 
	 *         match this info
	 */
	FGVertex getVertex(FGController controller, Map<AddressHasher, FGVertex> vertexMap) {
		return getVertex(controller, vertexMap, vertexAddressInfo);
	}

	private FGVertex getVertex(FGController controller, Map<AddressHasher, FGVertex> vertexMap,
			AddressInfo addressInfo) {

		Program program = controller.getProgram();
		AddressFactory addressFactory = program.getAddressFactory();
		Address minAddress = addressFactory.getAddress(addressInfo.addressRangeStart);
		Address maxAddress = addressFactory.getAddress(addressInfo.addressRangeEnd);
		AddressHasher addressHasher = new AddressHasher(minAddress, maxAddress);
		FGVertex vertex = vertexMap.get(addressHasher);
		if (vertex == null) {
			return null;
		}

		vertex.setLocation(getVertexLocation());

		return vertex;
	}

	Set<FGEdge> getInEdges(FGController controller, FGVertex vertex) {

		Set<FGEdge> edges = new HashSet<>();
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGEdge> inEdges = graph.getInEdges(vertex);
		if (inEdges == null) {
			return null;
		}

		edges.addAll(inEdges);
		return edges;
	}

	Set<FGEdge> getOutEdges(FGController controller, FGVertex vertex) {

		Set<FGEdge> edges = new HashSet<>();
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGEdge> outEdges = graph.getOutEdges(vertex);
		if (outEdges == null) {
			return null;
		}

		edges.addAll(outEdges);
		return edges;
	}

	Point2D getVertexLocation() {
		return locationInfo.getPoint();
	}

	Element toXML() {
		Element vertexInfoElement = new Element(getVertexInfoElementName());

		//
		// sub-tags:
		// -address info
		// -location
		// -edge infos
		// --address info
		// --flow type
		// --articulation points
		vertexAddressInfo.write(vertexInfoElement);

		Element locationElement = new Element(LOCATION_INFO_ELEMENT_NAME);
		locationInfo.write(locationElement);
		vertexInfoElement.addContent(locationElement);
		return vertexInfoElement;
	}

	protected String getVertexInfoElementName() {
		return VERTEX_INFO_ELEMENT_NAME;
	}
}
