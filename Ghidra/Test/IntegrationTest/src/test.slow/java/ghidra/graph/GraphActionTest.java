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
package ghidra.graph;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import docking.widgets.dialogs.MultiLineInputDialog;
import ghidra.app.plugin.core.graph.GraphDisplayBrokerPlugin;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.visualization.DefaultGraphDisplayComponentProvider;
import ghidra.graph.visualization.GroupVertex;
import ghidra.service.graph.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class GraphActionTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AttributedGraph graph;
	private ComponentProvider graphComponentProvider;
	private GraphDisplay display;
	private GraphSpy graphSpy = new GraphSpy();
	private AttributedVertex a;
	private AttributedVertex b;
	private AttributedVertex c;
	private AttributedVertex d;
	private AttributedVertex e;
	private AttributedVertex f;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.launchDefaultTool();
		tool.addPlugin(GraphDisplayBrokerPlugin.class.getName());
		graph = createGraph();

		showGraph();

		graphComponentProvider = tool.getComponentProvider("graph");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testSelectVertexAction() {
		assertTrue(display.getSelectedVertices().isEmpty());

		DockingActionIf action = getAction(tool, "Select Vertex");
		VertexGraphActionContext context =
			new VertexGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getVertex("B"));
		performAction(action, context, true);

		Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
		assertEquals(1, selectedVertices.size());
		assertTrue(selectedVertices.contains(b));

		// now try and select a second vertex
		context = new VertexGraphActionContext(graphComponentProvider, graph, null, null, d);
		performAction(action, context, true);
		selectedVertices = display.getSelectedVertices();
		assertEquals(2, selectedVertices.size());
		assertTrue(selectedVertices.contains(b));
		assertTrue(selectedVertices.contains(d));

	}

	@Test
	public void testDeSelectVertexAction() {
		select(a, b, c, d);
		assertEquals(4, display.getSelectedVertices().size());

		DockingActionIf action = getAction(tool, "Deselect Vertex");
		VertexGraphActionContext context =
			new VertexGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getVertex("B"));
		performAction(action, context, true);

		Set<AttributedVertex> selected = display.getSelectedVertices();
		assertEquals(3, selected.size());
		assertTrue(selected.contains(a));
		assertTrue(selected.contains(c));
		assertTrue(selected.contains(d));
		assertFalse(selected.contains(b));

	}

	@Test
	public void testSelectEdgeAction() {
		assertTrue(display.getSelectedVertices().isEmpty());

		DockingActionIf action = getAction(tool, "Select Edge");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		Set<AttributedVertex> selectedVerticeIds = display.getSelectedVertices();
		assertEquals(2, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains(a));
		assertTrue(selectedVerticeIds.contains(b));
	}

	@Test
	public void testDeSelectEdgeAction() {
		DockingActionIf action = getAction(tool, "Select Edge");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
		assertEquals(2, selectedVertices.size());

		action = getAction(tool, "Deselect Edge");

		performAction(action, context, true);

		selectedVertices = display.getSelectedVertices();
		assertEquals(0, selectedVertices.size());
	}

	@Test
	public void testSelectEdgeSource() {
		setFocusedVertex(d);
		DockingActionIf action = getAction(tool, "Edge Source");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		assertEquals(a, display.getFocusedVertex());
	}

	@Test
	public void testSelectEdgeTarget() {
		setFocusedVertex(d);
		DockingActionIf action = getAction(tool, "Edge Target");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(a, b));
		performAction(action, context, true);

		assertEquals(b, display.getFocusedVertex());
	}

	@Test
	public void testInvertSelection() {
		select(a, c, e);
		DockingActionIf action = getAction(tool, "Invert Selection");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
		assertEquals(3, selectedVertices.size());
		assertTrue(selectedVertices.contains(b));
		assertTrue(selectedVertices.contains(d));
		assertTrue(selectedVertices.contains(f));
	}

	@Test
	public void testGrowSelectionOut() {
		select(a);
		DockingActionIf action = getAction(tool, "Grow Selection To Targets");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		Set<AttributedVertex> selectedVerticeIds = display.getSelectedVertices();
		assertEquals(3, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains(a));
		assertTrue(selectedVerticeIds.contains(b));
		assertTrue(selectedVerticeIds.contains(c));
	}

	@Test
	public void testGrowSelectionIn() {
		select(d);
		DockingActionIf action = getAction(tool, "Grow Selection From Sources");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
		assertEquals(3, selectedVertices.size());
		assertTrue(selectedVertices.contains(d));
		assertTrue(selectedVertices.contains(b));
		assertTrue(selectedVertices.contains(c));
	}

	@Test
	public void testCreateSubGraph() {
		List<DefaultGraphDisplayComponentProvider> graphProviders = tool.getWindowManager()
				.getComponentProviders(DefaultGraphDisplayComponentProvider.class);

		assertEquals(1, graphProviders.size());
		DefaultGraphDisplayComponentProvider original = graphProviders.get(0);

		select(b, c, d);
		DockingActionIf action = getAction(tool, "Create Subgraph");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		graphProviders = tool.getWindowManager()
				.getComponentProviders(DefaultGraphDisplayComponentProvider.class);

		assertEquals(2, graphProviders.size());
		DefaultGraphDisplayComponentProvider newProvider = graphProviders.get(0);
		if (newProvider == original) {
			newProvider = graphProviders.get(1);
		}
		GraphActionContext actionContext = (GraphActionContext) newProvider.getActionContext(null);
		AttributedGraph newGraph = actionContext.getGraph();
		assertEquals(3, newGraph.getVertexCount());
		assertFalse(contains(newGraph, "A"));
		assertTrue(contains(newGraph, "B"));
		assertTrue(contains(newGraph, "C"));
		assertTrue(contains(newGraph, "D"));
		assertFalse(contains(newGraph, "E"));
		assertFalse(contains(newGraph, "F"));
	}

	@Test
	public void testCollapseVertices() {
		assertEquals(6, display.getGraph().getVertexCount());
		select(a, b, c);

		collapse();

		assertEquals(4, graph.getVertexCount());
		GroupVertex groupVertex = findGroupVertex();
		Set<AttributedVertex> containedVertices = groupVertex.getContainedVertices();
		assertEquals(3, containedVertices.size());
		assertTrue(containedVertices.contains(a));
		assertTrue(containedVertices.contains(b));
		assertTrue(containedVertices.contains(c));
	}

	@Test
	public void testExpandVertices() {
		assertEquals(6, display.getGraph().getVertexCount());
		select(a, b, c);

		collapse();

		assertEquals(4, graph.getVertexCount());
		GroupVertex groupVertex = findGroupVertex();
		assertNotNull(groupVertex);
		select(groupVertex);

		expand();
		assertEquals(6, graph.getVertexCount());
		groupVertex = findGroupVertex();
		assertNull(groupVertex);
	}

	@Test
	public void testSelectNodeThatIsGrouped() {
		select(a, b, c);
		collapse();

		clearSelection();
		assertTrue(display.getSelectedVertices().isEmpty());

		// 'b' is inside the group, selecting 'b' should select the group node
		select(b);

		Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
		assertEquals(1, selectedVertices.size());
		AttributedVertex vertex = selectedVertices.iterator().next();
		assertTrue(vertex instanceof GroupVertex);

	}

	// @Test TODO GP-658
	public void testSelectNodeThatIsDoubleGrouped() {
		select(a, b, c);
		collapse();
		select(findGroupVertex(), d);
		collapse();

		clearSelection();
		assertTrue(display.getSelectedVertices().isEmpty());

		select(b);
		Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
		assertEquals(1, selectedVertices.size());
		AttributedVertex vertex = selectedVertices.iterator().next();
		assertTrue(vertex instanceof GroupVertex);
		assertEquals(4, ((GroupVertex) vertex).getContainedVertices().size());

	}

	@Test
	public void testFocusNodeThatIsGrouped() {
		select(a, b, c);
		collapse();

		clearSelection();
		assertTrue(display.getSelectedVertices().isEmpty());

		setFocusedVertex(b);

		AttributedVertex vertex = display.getFocusedVertex();
		assertTrue(vertex instanceof GroupVertex);
	}

	// @Test TODO GP-658
	public void testFocusNodeThatIsDoubleGrouped() {
		select(a, b, c);
		collapse();
		select(findGroupVertex(), d);
		collapse();
		setFocusedVertex(e);
		assertEquals(e, display.getFocusedVertex());

		setFocusedVertex(b);

		AttributedVertex vertex = display.getFocusedVertex();
		assertTrue(vertex instanceof GroupVertex);
		assertEquals(4, ((GroupVertex) vertex).getContainedVertices().size());
	}

	@Test
	public void testListenerNotificatinWhenGroupNodeFocused() {
		select(a, b, c);
		collapse();
		GroupVertex group = findGroupVertex();
		setFocusedVertex(e);

		graphSpy.clear();
		setFocusedVertex(group, true);
		waitForSwing();

		assertTrue(graphSpy.isFocused(a));
	}

	// @Test TODO GP-658
	public void testListenerNotificatinWhenDoubleGroupedNodeFocused() {
		select(a, b, c);
		collapse();
		select(findGroupVertex(), d);
		collapse();

		GroupVertex group = findGroupVertex();
		setFocusedVertex(e);

		graphSpy.clear();
		setFocusedVertex(group, true);

		waitForSwing();
		assertTrue(graphSpy.isFocused(a));
	}

	@Test
	public void testSelectNotificatinWhenGroupNodeFocused() {
		select(a, b, c);
		collapse();
		GroupVertex group = findGroupVertex();
		clearSelection();
		graphSpy.clear();
		selectFromGui(group);

		waitForSwing();
		assertTrue(graphSpy.isSelected(a, b, c));
	}

	// @Test TODO GP-658
	public void testSelectNotificatinWhenDoubleGroupedNodeFocused() {
		select(a, b, c);
		collapse();
		select(findGroupVertex(), d);
		collapse();

		GroupVertex group = findGroupVertex();
		clearSelection();
		graphSpy.clear();
		selectFromGui(group);

		waitForSwing();
		assertTrue(graphSpy.isSelected(a, b, c, d));
	}

	private void clearSelection() {
		select();
	}

	private void collapse() {
		DockingActionIf action = getAction(tool, "Collapse Selected");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, false);
		MultiLineInputDialog dialog = waitForDialogComponent(MultiLineInputDialog.class);
		pressButtonByText(dialog, "OK", true);
	}

	private void expand() {
		DockingActionIf action = getAction(tool, "Expand Selected");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);
	}

	private GroupVertex findGroupVertex() {
		for (AttributedVertex vertex : graph.vertexSet()) {
			if (vertex instanceof GroupVertex) {
				return (GroupVertex) vertex;
			}
		}
		return null;
	}

	private boolean contains(AttributedGraph g, String vertexId) {
		return g.getVertex(vertexId) != null;
	}

	private void showGraph() throws Exception {
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider service = broker.getGraphDisplayProvider("Default Graph Display");
		display = service.getGraphDisplay(false, TaskMonitor.DUMMY);
		display.setGraph(graph, "test graph", false, TaskMonitor.DUMMY);
		display.setGraphDisplayListener(new TestGraphDisplayListener("test"));
	}

	private void select(AttributedVertex... vertices) {
		runSwing(() -> {
			Set<AttributedVertex> vetexSet = new HashSet<>(Arrays.asList(vertices));
			display.selectVertices(vetexSet, EventTrigger.INTERNAL_ONLY);
		});
	}

	private void selectFromGui(AttributedVertex... vertices) {
		runSwing(() -> {
			Set<AttributedVertex> vetexSet = new HashSet<>(Arrays.asList(vertices));
			display.selectVertices(vetexSet, EventTrigger.GUI_ACTION);
		});
	}

	private void setFocusedVertex(AttributedVertex vertex) {
		setFocusedVertex(vertex, false);
	}

	private void setFocusedVertex(AttributedVertex vertex, boolean fireEvent) {
		EventTrigger trigger = fireEvent ? EventTrigger.GUI_ACTION : EventTrigger.INTERNAL_ONLY;
		runSwing(() -> display.setFocusedVertex(vertex, trigger));
	}

	class TestGraphDisplayListener implements GraphDisplayListener {

		private String name;

		TestGraphDisplayListener(String name) {
			this.name = name;
		}

		@Override
		public void graphClosed() {
			// do nothing
		}

		@Override
		public void selectionChanged(Set<AttributedVertex> vertices) {
			graphSpy.setSelection(vertices);
		}

		@Override
		public void locationFocusChanged(AttributedVertex vertex) {
			graphSpy.focusChanged(vertex);
		}

		@Override
		public GraphDisplayListener cloneWith(GraphDisplay graphDisplay) {
			return new TestGraphDisplayListener("clone");
		}

		@Override
		public void dispose() {
			// do nothing
		}

	}

	class GraphSpy {
		AttributedVertex focusedVertex;
		Set<AttributedVertex> selectedVertices;

		public void focusChanged(AttributedVertex vertex) {
			this.focusedVertex = vertex;
		}

		public boolean isSelected(AttributedVertex... vertices) {
			Set<AttributedVertex> expected = new HashSet<>(Arrays.asList(vertices));
			return expected.equals(selectedVertices);
		}

		public boolean isFocused(AttributedVertex a) {
			return a == focusedVertex;
		}

		public void clear() {
			focusedVertex = null;
			selectedVertices = null;
		}

		public void setSelection(Set<AttributedVertex> vertices) {
			this.selectedVertices = vertices;
		}

	}

	private AttributedGraph createGraph() {
		AttributedGraph g = new AttributedGraph();
		a = g.addVertex("A");
		b = g.addVertex("B");
		c = g.addVertex("C");
		d = g.addVertex("D");
		e = g.addVertex("E");
		f = g.addVertex("F");

		g.addEdge(a, b);
		g.addEdge(a, c);
		g.addEdge(b, d);
		g.addEdge(b, f);
		g.addEdge(c, d);
		g.addEdge(d, e);
		g.addEdge(e, f);

		return g;
	}

}
