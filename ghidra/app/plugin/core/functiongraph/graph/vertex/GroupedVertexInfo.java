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

import java.awt.Color;
import java.awt.geom.Point2D;
import java.util.*;

import org.jdom.Element;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * Note: this class should be created along with a GroupedFunctionGraphVertex, as the info
 * needed by this class is still available then.  To create this class later will result in
 * missing information (for example, edges get removed when vertices are grouped and this info
 * object will collect edge information, but cannot do so if they have been removed from the 
 * graph).
 */
class GroupedVertexInfo extends VertexInfo {

	static final String GROUPED_VERTEX_INFO_ELEMENT_NAME = "GROUPED_VERTEX_INFO";
	private static final String USER_TEXT_ATTRIBUTE = "USER_TEXT";
	private static final String BACKGROUND_COLOR_ATTRIBUTE = "BACKGROUND_COLOR";

	private Set<VertexInfo> vertexInfos = new HashSet<>();

	private String userText;
	private Color backgroundColor;

	GroupedVertexInfo(GroupedFunctionGraphVertex vertex, FunctionGraph functionGraph) {
		super(vertex, functionGraph);

		Set<FGVertex> vertices = vertex.getVertices();
		for (FGVertex childVertex : vertices) {
			if (childVertex instanceof GroupedFunctionGraphVertex) {
				vertexInfos.add(
					new GroupedVertexInfo((GroupedFunctionGraphVertex) childVertex, functionGraph));
			}
			else {
				vertexInfos.add(new VertexInfo(childVertex, functionGraph));
			}
		}

		userText = vertex.getUserText();
		backgroundColor = vertex.getBackgroundColor();
	}

	@SuppressWarnings("unchecked")
	GroupedVertexInfo(Element element) {
		super(element);

		List<Element> children = element.getChildren(VERTEX_INFO_ELEMENT_NAME);
		for (Element vertexInfoElement : children) {
			vertexInfos.add(new VertexInfo(vertexInfoElement));
		}

		children = element.getChildren(GROUPED_VERTEX_INFO_ELEMENT_NAME);
		for (Element groupedVertexInfoElement : children) {
			vertexInfos.add(new GroupedVertexInfo(groupedVertexInfoElement));
		}

		if (vertexInfos.isEmpty()) {
			throw new IllegalArgumentException(
				"Saved GroupedVertexInfo XML does not have child vertices");
		}

		userText =
			XmlUtilities.unEscapeElementEntities(element.getAttributeValue(USER_TEXT_ATTRIBUTE));
		backgroundColor = decodeColor(element.getAttributeValue(BACKGROUND_COLOR_ATTRIBUTE));
	}

	private Color decodeColor(String colorString) {
		if (colorString == null) {
			return FunctionGraphOptions.DEFAULT_GROUP_BACKGROUND_COLOR;
		}

		StringTokenizer tokenizer = new StringTokenizer(colorString, ",");
		int tokenCount = tokenizer.countTokens();
		if (tokenCount != 4) {
			return FunctionGraphOptions.DEFAULT_GROUP_BACKGROUND_COLOR;
		}

		String redString = tokenizer.nextToken();
		String greenString = tokenizer.nextToken();
		String blueString = tokenizer.nextToken();
		String alphaString = tokenizer.nextToken();

		try {
			int red = Integer.parseInt(redString);
			int green = Integer.parseInt(greenString);
			int blue = Integer.parseInt(blueString);
			int alpha = Integer.parseInt(alphaString);
			return new Color(red, green, blue, alpha);
		}
		catch (NumberFormatException e) {
			Msg.error(this, "Unexpected exception parsing number", e);
			return FunctionGraphOptions.DEFAULT_GROUP_BACKGROUND_COLOR;
		}
	}

	private String encodeColor(Color color) {
		if (color == null) {
			return encodeColor(FunctionGraphOptions.DEFAULT_GROUP_BACKGROUND_COLOR);
		}
		return color.getRed() + "," + color.getGreen() + "," + color.getBlue() + "," +
			color.getAlpha();
	}

	@Override
	Element toXML() {
		// this call will put all the basic info into the element
		Element element = super.toXML();

		// we now need to put the xml for the grouped vertices into the element
		for (VertexInfo info : vertexInfos) {
			Element vertexElement = info.toXML();
			element.addContent(vertexElement);
		}

		// user defined text to display in the vertex
		String escapedText = XmlUtilities.escapeElementEntities(userText);
		element.setAttribute(USER_TEXT_ATTRIBUTE, escapedText);

		// background color
		element.setAttribute(BACKGROUND_COLOR_ATTRIBUTE, encodeColor(backgroundColor));

		return element;
	}

	/**
	 * Locates a vertex for the given info <b>without creating that vertex</b>.  This is in 
	 * contrast to {@link #getVertex(FGController, Map)}, which will create a vertex
	 * (and supporting vertices if it is a group).
	 * 
	 * @param controller the controller of the current graph
	 * @param vertexMap a mapping of hashed addresses to vertices (creating this upfront is more
	 *        efficient when using it over different {@link GroupedVertexInfo} instances.
	 * @return an existing vertex; null if one does not exist
	 */
	FGVertex locateVertex(FGController controller, Map<AddressHasher, FGVertex> vertexMap) {
		return super.getVertex(controller, vertexMap);
	}

	@Override
	FGVertex getVertex(FGController controller, Map<AddressHasher, FGVertex> vertexMap) {

// 7937:D - when we can't find a grouped vertex after restoring from XML, do we give 
//		             up completely?  Do we just ignore that vertex and keep grouping others?

		//
		// GroupedVertexInfos must be processed first, as they are processed, they will remove
		// edges from the graph that should not be in the final GroupedVertex created here.  Also,
		// we need any edges for the subgroups to exist in the graph so that the group vertex
		// created here will get those edges.
		//
		Set<GroupedVertexInfo> groupInfos = getGroupVertexInfos(vertexInfos);

		Set<FGVertex> vertices = new HashSet<>();
		Set<FGEdge> edges = new HashSet<>();
		createVertexAndEdges(controller, vertexMap, groupInfos, vertices, edges);

		//
		// Now process the remaining non-group infos
		//
		HashSet<VertexInfo> nonGroupInfos = new HashSet<>(vertexInfos);
		nonGroupInfos.removeAll(groupInfos); // what's left is the vertex infos
		createVertexAndEdges(controller, vertexMap, nonGroupInfos, vertices, edges);

		if (vertices.isEmpty()) {
			// this implies the graph structure has changes such that the originally grouped
			// blocks no longer exist
			return null;
		}

		GroupedFunctionGraphVertex vertex =
			new GroupedFunctionGraphVertex(controller, userText, vertices, edges);
		Color defaultBackgroundColor = vertex.getDefaultBackgroundColor();
		if (!defaultBackgroundColor.equals(backgroundColor)) {
			vertex.setBackgroundColor(backgroundColor);
		}

		return vertex;
	}

	private void createVertexAndEdges(FGController controller,
			Map<AddressHasher, FGVertex> vertexMap, Set<? extends VertexInfo> infos,
			Set<FGVertex> vertices, Set<FGEdge> edges) {
		for (VertexInfo info : infos) {
			FGVertex vertex = info.getVertex(controller, vertexMap);
			if (vertex == null) {
				continue; // can no longer find a vertex with the given info
			}

			vertex = checkForGroupVertex(controller, vertex, info.getVertexLocation());
			if (vertex == null) {
				continue; // couldn't install group vertex
			}

			Set<FGEdge> restoredInEdges = info.getInEdges(controller, vertex);
			if (restoredInEdges == null) {
				continue; // can no longer find the previous edges
			}

			Set<FGEdge> restoredOutEdges = info.getOutEdges(controller, vertex);
			if (restoredOutEdges == null) {
				continue; // can no longer find the previous edges
			}

			vertices.add(vertex);
			edges.addAll(restoredInEdges);
			edges.addAll(restoredOutEdges);
		}
	}

	private Set<GroupedVertexInfo> getGroupVertexInfos(Set<VertexInfo> allInfos) {
		Set<GroupedVertexInfo> groupInfos = new HashSet<>();
		for (VertexInfo info : allInfos) {
			if (info instanceof GroupedVertexInfo) {
				groupInfos.add((GroupedVertexInfo) info);
			}
		}
		return groupInfos;
	}

	private FGVertex checkForGroupVertex(FGController controller, FGVertex vertex,
			Point2D location) {

		if (!(vertex instanceof GroupedFunctionGraphVertex)) {
			return vertex;
		}

		// Make sure this vertex is added to the graph.  We have to do this here, as 
		// this method getVertex() is recursive and we cannot build-up the edges of 
		// lower-level grouped nodes if they have never been added to the graph.
		boolean installed =
			controller.installGroupVertex((GroupedFunctionGraphVertex) vertex, location);
		return installed ? vertex : null;
	}

	@Override
	protected String getVertexInfoElementName() {
		return GROUPED_VERTEX_INFO_ELEMENT_NAME;
	}

	@Override
	public String toString() {
		String superString = super.toString();
		StringBuffer buffy = new StringBuffer(superString);
		buffy.append('\n');
		for (VertexInfo info : vertexInfos) {
			buffy.append('\t').append(info.toString()).append('\n');
		}

		return buffy.toString();
	}
}
