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

import java.awt.Point;
import java.awt.geom.Point2D;
import java.util.*;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FGVertexType;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

public class GroupedFunctionGraphVertex extends AbstractFunctionGraphVertex {

	private GroupedFunctionGraphComponentPanel component;

	private final Set<FGVertex> vertices;

	/**
	 * The edges that existed before this group node was created
	 * 
	 * @see #convertGroupedEdge(FGEdge, Set)
	 */
	private Set<FGEdge> ungroupedEdges;

	/**
	 * We need this in the use case that we do NOT relayout the graph each time we group. These
	 * values allow us to restore the vertices to the place from whence they came (even though 
	 * the locations may be irrelevant).
	 */
	private Map<FGVertex, Point2D> preGroupingVertexLocations = new HashMap<>();

	private boolean doHashCode = true;
	private int hashCode;

	private GroupListener groupListener;
	private String initialGroupVertexUserText;

	private static AddressSetView gatherAddresses(Program program, Set<FGVertex> vertices) {
		if (vertices.size() == 0) {
			throw new IllegalArgumentException(
				"Cannot create a group vertex with no grouped vertices");
		}

		AddressSet addresses = new AddressSet();
		for (FGVertex vertex : vertices) {
			addresses.add(vertex.getAddresses());
		}
		return addresses;
	}

	private static boolean isEntry(Set<FGVertex> vertices) {
		for (FGVertex vertex : vertices) {
			FGVertexType vertexType = vertex.getVertexType();
			if (vertexType == FGVertexType.ENTRY) {
				return true;
			}
		}
		return false;
	}

	public GroupedFunctionGraphVertex(FGController controller, String groupVertexUserText,
			Set<FGVertex> vertices, Set<FGEdge> ungroupedEdges) {
		super(controller, controller.getProgram(),
			gatherAddresses(controller.getProgram(), vertices),
			RefType.FALL_THROUGH /* not sure here */, isEntry(vertices));

		this.ungroupedEdges = convertGroupedEdgeEndpoints(ungroupedEdges);
		this.vertices = new HashSet<>(vertices);
		this.initialGroupVertexUserText = groupVertexUserText;
		setVertexType(pickType());

		preGroupingVertexLocations = getCurrentVertexLocations();
	}

	private Set<FGEdge> convertGroupedEdgeEndpoints(Set<FGEdge> unvalidatedEdges) {

		Set<FGEdge> updatedEdges = new HashSet<>(unvalidatedEdges.size());
		for (FGEdge edge : unvalidatedEdges) {
			convertGroupedEdge(edge, updatedEdges);
		}

		return updatedEdges;
	}

	/**
	 * Seriously complicated algorithm (conceptually) to ensure that we never store in our 
	 * collection of ungrouped edges (which we may sometime have to re-install) any group vertex, 
	 * as when we go to restore the edges, we do not know how to do so if the group is no 
	 * longer there (like as a result of an ungroup operation).
	 *   
	 * @param edge the edge to resolve/convert from using group vertices as endpoints to using
	 *        real vertices as endpoints
	 * @param updatedEdges all edges that we must record as a result of ungrouping the given edge
	 */
	private void convertGroupedEdge(FGEdge edge, Set<FGEdge> updatedEdges) {
		FGVertex startVertex = edge.getStart();
		FGVertex destinationVertex = edge.getEnd();
		if (!eitherGroupedEndpoint(startVertex, destinationVertex)) {
			updatedEdges.add(edge); // plain old edge
			return;
		}

		// 
		// When both endpoints are groups, we want to get all edges in common for later restoring,
		// as we don't know which edges either group refers to if the group goes away
		//
		if (bothGroupedEndpoints(startVertex, destinationVertex)) {
			Set<FGEdge> intersectingConvertedEdges =
				getIntersectingEdges((GroupedFunctionGraphVertex) startVertex,
					(GroupedFunctionGraphVertex) destinationVertex);
			updatedEdges.addAll(intersectingConvertedEdges);
			return;
		}

		//
		// O.K., one of the endpoints is grouped.  Find out which one and get all edges that
		// have the same start/destination for later restoring,
		// as we don't know which edges the group refers to if the group goes away
		//
		if (startVertex instanceof GroupedFunctionGraphVertex) {
			Set<FGEdge> convertedDestinationEdges =
				((GroupedFunctionGraphVertex) startVertex).getAllEdgesWithDestination(
					destinationVertex);
			updatedEdges.addAll(convertedDestinationEdges);
		}
		else {
			Set<FGEdge> convertedStartEdges =
				((GroupedFunctionGraphVertex) destinationVertex).getAllEdgesWithStart(startVertex);
			updatedEdges.addAll(convertedStartEdges);
		}
	}

	private Set<FGEdge> getIntersectingEdges(GroupedFunctionGraphVertex startGroup,
			GroupedFunctionGraphVertex destinationGroup) {

		Set<FGEdge> startGroupEdges = startGroup.getUngroupedEdges();
		Set<FGEdge> destinationGroupEdges = destinationGroup.getUngroupedEdges();
		Set<FGEdge> intersectingEdges = new HashSet<>();
		intersectingEdges.addAll(startGroupEdges);
		intersectingEdges.retainAll(destinationGroupEdges);
		return intersectingEdges;
	}

	private Set<FGEdge> getAllEdgesWithDestination(FGVertex destinationVertex) {

		Set<FGEdge> matchingEdges = new HashSet<>(ungroupedEdges.size());
		for (FGEdge edge : ungroupedEdges) {
			if (edge.getEnd().equals(destinationVertex)) {
				matchingEdges.add(edge);
			}
		}
		return matchingEdges;
	}

	private Set<FGEdge> getAllEdgesWithStart(FGVertex startVertex) {

		Set<FGEdge> matchingEdges = new HashSet<>(ungroupedEdges.size());
		for (FGEdge edge : ungroupedEdges) {
			if (edge.getStart().equals(startVertex)) {
				matchingEdges.add(edge);
			}
		}
		return matchingEdges;
	}

	private boolean bothGroupedEndpoints(FGVertex startVertex, FGVertex destinationVertex) {
		return startVertex instanceof GroupedFunctionGraphVertex &&
			destinationVertex instanceof GroupedFunctionGraphVertex;
	}

	private boolean eitherGroupedEndpoint(FGVertex startVertex, FGVertex destinationVertex) {
		return startVertex instanceof GroupedFunctionGraphVertex ||
			destinationVertex instanceof GroupedFunctionGraphVertex;
	}

	public GroupedFunctionGraphVertex derriveGroupVertex(Set<FGVertex> additionalGroupedVertices,
			String groupVertexText, Set<FGEdge> additionalUngroupedEdges) {

		HashSet<FGEdge> newEdges = new HashSet<>(ungroupedEdges);
		newEdges.addAll(additionalUngroupedEdges);

		HashSet<FGVertex> newVertices = new HashSet<>(vertices);
		newVertices.addAll(additionalGroupedVertices);

		GroupedFunctionGraphVertex newVertex =
			new GroupedFunctionGraphVertex(getController(), groupVertexText, newVertices, newEdges);

		return newVertex;
	}

	/**
	 * Creates a new group based upon this one, but with the given vertices (and incident edges)
	 * removed. 
	 * 
	 * @param verticesToRemove the vertices to not include in the new group
	 * @return the new group
	 */
	public GroupedFunctionGraphVertex removeAll(Set<FGVertex> verticesToRemove) {

		Set<FGEdge> newEdges = new HashSet<>(ungroupedEdges);
		for (FGVertex vertex : verticesToRemove) {
			removeIncidentEdges(vertex, newEdges);
		}

		Set<FGVertex> newVertices = new HashSet<>(vertices);
		newVertices.removeAll(verticesToRemove);

		if (newVertices.isEmpty()) {
			return null;
		}

		GroupedFunctionGraphVertex newVertex =
			new GroupedFunctionGraphVertex(getController(), getUserText(), newVertices, newEdges);

		return newVertex;
	}

	private void removeIncidentEdges(FGVertex vertex, Set<FGEdge> newEdges) {
		for (FGEdge edge : ungroupedEdges) {
			if (vertex.equals(edge.getStart()) || vertex.equals(edge.getEnd())) {
				newEdges.remove(edge);
			}
		}
	}

	private Map<FGVertex, Point2D> getCurrentVertexLocations() {
		FGController fgController = getController();
		FGView view = fgController.getView();
		VisualizationViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
		Layout<FGVertex, FGEdge> graphLayout = viewer.getGraphLayout();
		Graph<FGVertex, FGEdge> graph = graphLayout.getGraph();
		Collection<FGVertex> currentVertices = graph.getVertices();
		Map<FGVertex, Point2D> map = new HashMap<>();
		for (FGVertex vertex : currentVertices) {
			if (vertex == this) {
				// not sure if we need to do this, but, conceptually, we are getting the locations
				// in the graph before this group node is installed
				continue;
			}
			Point2D point2D = graphLayout.apply(vertex);
			map.put(vertex, new Point((int) point2D.getX(), (int) point2D.getY()));
		}
		return map;
	}

//	private Image createGraphImage() {
//
//		FunctionGraphController controller = getController();
//		FunctionGraphView view = controller.getView();
//		FunctionGraphPrimaryViewer viewer = view.getPrimaryGraphViewer();
//
//		Dimension size = viewer.getSize();
//		BufferedImage image =
//			new BufferedImage(size.width, size.height, BufferedImage.TYPE_INT_ARGB);
//		Graphics2D graphics = (Graphics2D) image.getGraphics();
//
//		viewer.paint(graphics);
//		graphics.dispose();
//
//		Dimension d = new Dimension(150, 400);
//		BufferedImage scaledImage =
//			new BufferedImage(d.width, d.height, BufferedImage.TYPE_INT_ARGB);
//		graphics = (Graphics2D) scaledImage.getGraphics();
//		Graphics2D g2 = graphics;
//		g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
//			RenderingHints.VALUE_INTERPOLATION_BILINEAR);
//		graphics.drawImage(image, 0, 0, d.width, d.height, null);
//		graphics.dispose();
//
//		return scaledImage;
//	}

	private FGVertexType pickType() {
		boolean hasEntry = false;
		boolean hasExit = false;
		for (FGVertex vertex : vertices) {
			FGVertexType vertexType = vertex.getVertexType();
			if (vertexType == FGVertexType.ENTRY) {
				hasEntry = true;
			}
			else if (vertexType == FGVertexType.EXIT) {
				hasExit = true;
			}
		}

		if (hasEntry) {
			return FGVertexType.ENTRY;
		}

		if (hasExit) {
			return FGVertexType.EXIT;
		}

		return FGVertexType.GROUP;
	}

	@Override
	public void writeSettings(FunctionGraphVertexAttributes settings) {
		for (FGVertex vertex : vertices) {
			vertex.writeSettings(settings);
		}
	}

	@Override
	public void readSettings(FunctionGraphVertexAttributes settings) {
		for (FGVertex vertex : vertices) {
			vertex.readSettings(settings);
		}
	}

	@Override
	public FGVertex cloneVertex(FGController newController) {
		throw new UnsupportedOperationException("cloneVertex() unsupported--not needed");
	}

	@Override
	boolean hasLoadedComponent() {
		return component != null;
	}

	@Override
	AbstractGraphComponentPanel doGetComponent() {
		if (component == null) {
			SystemUtilities.assertThisIsTheSwingThread(
				"Cannot create vertex " + "component off of the Swing thread");

			component = new GroupedFunctionGraphComponentPanel(getController(), this,
				initialGroupVertexUserText);

			if (pendingRestoreColor != null) {
				component.restoreColor(pendingRestoreColor);
				pendingRestoreColor = null;
			}
		}
		return component;
	}

	@Override
	public void dispose() {
		groupListener = null;

		for (FGVertex vertex : vertices) {
			vertex.dispose();
		}
		vertices.clear();
		super.dispose();
	}

	public String getUserText() {
		return ((GroupedFunctionGraphComponentPanel) doGetComponent()).getUserText();
	}

	void userTextChanged(String oldText, String text) {
		groupListener.groupDescriptionChanged(oldText, text);
	}

	public void addGroupListener(GroupListener listener) {
		if (groupListener != null) {
			throw new AssertException("Update code to handle multiple listeners!");
		}

		groupListener = listener;
	}

	public void removeGroupListener(GroupListener listener) {
		if (groupListener != null && groupListener != listener) {
			throw new AssertException("Update code to handle multiple listeners!");
		}

		groupListener = null;
	}

	public Set<FGVertex> getVertices() {
		return Collections.unmodifiableSet(vertices);
	}

	public Set<FGEdge> getUngroupedEdges() {
		return Collections.unmodifiableSet(ungroupedEdges);
	}

	public Map<FGVertex, Point2D> getPreGroupLocations() {
		return Collections.unmodifiableMap(preGroupingVertexLocations);
	}

	public static String generateGroupVertexDescription(Set<FGVertex> vertices) {
		ArrayList<FGVertex> sortedList = new ArrayList<>(vertices);
		Collections.sort(sortedList, (v1, v2) -> {
			Address a1 = v1.getVertexAddress();
			Address a2 = v2.getVertexAddress();
			return a1.compareTo(a2);
		});

		StringBuilder buffy = new StringBuilder();
		for (FGVertex subVertex : sortedList) {
			if (subVertex instanceof GroupedFunctionGraphVertex) {
				buffy.append("Group Vertex").append('\n');
				String text = ((GroupedFunctionGraphVertex) subVertex).getUserText();
				StringTokenizer tokenizzy = new StringTokenizer(text, "\n");
				while (tokenizzy.hasMoreTokens()) {
					buffy.append('\t').append(tokenizzy.nextToken()).append('\n');
				}
			}
			else {
				buffy.append(getVertexDescription(subVertex));
			}

			buffy.append('\n');
		}
		return buffy.toString();
	}

	public static String getVertexDescription(FGVertex vertex) {
		return "Vertex: " + vertex.getTitle();
	}

	@Override
	public int hashCode() {
		if (doHashCode) {
			hashCode = vertices.hashCode();
			doHashCode = false;
		}

		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		GroupedFunctionGraphVertex other = (GroupedFunctionGraphVertex) obj;
		Set<FGVertex> otherVertices = other.getVertices();
		return vertices.equals(otherVertices);
	}
}
