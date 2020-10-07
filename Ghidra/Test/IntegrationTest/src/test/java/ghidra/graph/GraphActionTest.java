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
import ghidra.app.plugin.core.graph.GraphDisplayBrokerPlugin;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.visualization.DefaultGraphDisplayComponentProvider;
import ghidra.service.graph.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class GraphActionTest extends AbstractGhidraHeadedIntegrationTest {
	private List<String> listenerCalls = new ArrayList<>();
	private TestEnv env;
	private PluginTool tool;
	private AttributedGraph graph;
	private ComponentProvider graphComponentProvider;
	private GraphDisplay display;

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
		assertTrue(display.getSelectedVertexIds().isEmpty());

		DockingActionIf action = getAction(tool, "Select Vertex");
		VertexGraphActionContext context =
			new VertexGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getVertex("B"));
		performAction(action, context, true);

		Set<String> selectedVertexIds = display.getSelectedVertexIds();
		assertEquals(1, selectedVertexIds.size());
		assertTrue(selectedVertexIds.contains(graph.getVertex("B").getId()));

		// now try and select a second vertex
		context = new VertexGraphActionContext(graphComponentProvider, graph, null, null,
			graph.getVertex("D"));
		performAction(action, context, true);
		selectedVertexIds = display.getSelectedVertexIds();
		assertEquals(2, selectedVertexIds.size());
		assertTrue(selectedVertexIds.contains(graph.getVertex("B").getId()));
		assertTrue(selectedVertexIds.contains(graph.getVertex("D").getId()));

	}

	@Test
	public void testDeSelectVertexAction() {
		display.selectVertices(Arrays.asList("A", "B", "C", "D"), EventTrigger.API_CALL);
		assertEquals(4, display.getSelectedVertexIds().size());

		DockingActionIf action = getAction(tool, "Deselect Vertex");
		VertexGraphActionContext context =
			new VertexGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getVertex("B"));
		performAction(action, context, true);

		Set<String> selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(3, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains(graph.getVertex("A").getId()));
		assertTrue(selectedVerticeIds.contains(graph.getVertex("D").getId()));
		assertTrue(selectedVerticeIds.contains(graph.getVertex("D").getId()));
		assertFalse(selectedVerticeIds.contains(graph.getVertex("B").getId()));

	}

	@Test
	public void testSelectEdgeAction() {
		assertTrue(display.getSelectedVertexIds().isEmpty());

		DockingActionIf action = getAction(tool, "Select Edge");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		Set<String> selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(2, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains(graph.getVertex("A").getId()));
		assertTrue(selectedVerticeIds.contains(graph.getVertex("B").getId()));
	}

	@Test
	public void testDeSelectEdgeAction() {
		DockingActionIf action = getAction(tool, "Select Edge");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		Set<String> selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(2, selectedVerticeIds.size());

		action = getAction(tool, "Deselect Edge");

		performAction(action, context, true);

		selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(0, selectedVerticeIds.size());

	}

	@Test
	public void testSelectEdgeSource() {
		display.setLocationFocus("D", EventTrigger.INTERNAL_ONLY);
		DockingActionIf action = getAction(tool, "Edge Source");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		assertEquals("A", display.getFocusedVertexId());
	}

	@Test
	public void testSelectEdgeTarget() {
		display.setLocationFocus("D", EventTrigger.INTERNAL_ONLY);
		DockingActionIf action = getAction(tool, "Edge Target");
		EdgeGraphActionContext context =
			new EdgeGraphActionContext(graphComponentProvider, graph, null, null,
				graph.getEdge(graph.getVertex("A"), graph.getVertex("B")));
		performAction(action, context, true);

		assertEquals("B", display.getFocusedVertexId());
	}

	@Test
	public void testInvertSelection() {
		display.selectVertices(List.of("A", "C", "E"), EventTrigger.INTERNAL_ONLY);
		DockingActionIf action = getAction(tool, "Invert Selection");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		Set<String> selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(3, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains("B"));
		assertTrue(selectedVerticeIds.contains("D"));
		assertTrue(selectedVerticeIds.contains("F"));
	}

	@Test
	public void testGrowSelectionOut() {
		display.selectVertices(List.of("A"), EventTrigger.INTERNAL_ONLY);
		DockingActionIf action = getAction(tool, "Grow Selection To Targets");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		Set<String> selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(3, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains("A"));
		assertTrue(selectedVerticeIds.contains("B"));
		assertTrue(selectedVerticeIds.contains("C"));
	}

	@Test
	public void testGrowSelectionIn() {
		display.selectVertices(List.of("D"), EventTrigger.INTERNAL_ONLY);
		DockingActionIf action = getAction(tool, "Grow Selection From Sources");
		GraphActionContext context =
			new GraphActionContext(graphComponentProvider, graph, null, null);
		performAction(action, context, true);

		Set<String> selectedVerticeIds = display.getSelectedVertexIds();
		assertEquals(3, selectedVerticeIds.size());
		assertTrue(selectedVerticeIds.contains("D"));
		assertTrue(selectedVerticeIds.contains("B"));
		assertTrue(selectedVerticeIds.contains("C"));
	}

	@Test
	public void testCreateSubGraph() {
		List<DefaultGraphDisplayComponentProvider> graphProviders = tool.getWindowManager()
				.getComponentProviders(DefaultGraphDisplayComponentProvider.class);

		assertEquals(1, graphProviders.size());
		DefaultGraphDisplayComponentProvider original = graphProviders.get(0);

		display.selectVertices(List.of("B", "C", "D"), EventTrigger.INTERNAL_ONLY);
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

	private boolean contains(AttributedGraph graph, String vertexId) {
		return graph.getVertex(vertexId) != null;
	}

	private void showGraph() throws Exception {
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider service = broker.getGraphDisplayProvider("Default Graph Display");
		display = service.getGraphDisplay(false, TaskMonitor.DUMMY);
		display.setGraph(graph, "test graph", false, TaskMonitor.DUMMY);
		display.setGraphDisplayListener(new TestGraphDisplayListener("test"));
	}

	class TestGraphDisplayListener implements GraphDisplayListener {

		private String name;

		TestGraphDisplayListener(String name) {
			this.name = name;
		}

		@Override
		public void graphClosed() {
			listenerCalls.add(name + ": graph closed");
		}

		@Override
		public void selectionChanged(List<String> vertexIds) {
			StringBuilder buf = new StringBuilder();
			buf.append(name);
			buf.append(": selected: ");
			for (String id : vertexIds) {
				buf.append(id);
				buf.append(",");
			}
			listenerCalls.add(buf.toString());
		}

		@Override
		public void locationFocusChanged(String vertexId) {
			listenerCalls.add(name + ": focus: " + vertexId);
		}

		@Override
		public GraphDisplayListener cloneWith(GraphDisplay graphDisplay) {
			return new TestGraphDisplayListener("clone");
		}

	}

	private AttributedGraph createGraph() {
		AttributedGraph g = new AttributedGraph();
		AttributedVertex a = g.addVertex("A");
		AttributedVertex b = g.addVertex("B");
		AttributedVertex c = g.addVertex("C");
		AttributedVertex d = g.addVertex("D");
		AttributedVertex e = g.addVertex("E");
		AttributedVertex f = g.addVertex("F");

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
