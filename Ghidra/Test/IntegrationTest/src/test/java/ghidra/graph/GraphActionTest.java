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
		context = new VertexGraphActionContext(graphComponentProvider, graph, null, null,d);
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

	private void setFocusedVertex(AttributedVertex vertex) {
		runSwing(() -> display.setFocusedVertex(vertex, EventTrigger.INTERNAL_ONLY));
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
		public void selectionChanged(Set<AttributedVertex> verrtices) {
			StringBuilder buf = new StringBuilder();
			buf.append(name);
			buf.append(": selected: ");
			for (AttributedVertex vertex : verrtices) {
				buf.append(vertex.getId());
				buf.append(",");
			}
			listenerCalls.add(buf.toString());
		}

		@Override
		public void locationFocusChanged(AttributedVertex vertex) {
			listenerCalls.add(name + ": focus: " + vertex.getId());
		}

		@Override
		public GraphDisplayListener cloneWith(GraphDisplay graphDisplay) {
			return new TestGraphDisplayListener("clone");
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
