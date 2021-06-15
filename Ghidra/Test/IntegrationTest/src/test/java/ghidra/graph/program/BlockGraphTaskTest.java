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
package ghidra.graph.program;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import ghidra.graph.TestGraphDisplay;
import ghidra.graph.TestGraphService;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.*;
import ghidra.util.task.TaskMonitor;

public class BlockGraphTaskTest extends AbstractBlockGraphTest {
	private static final boolean SHOW_CODE = true;
	private static final boolean DONT_SHOW_CODE = false;

	@Test
	public void testBlockGraph() throws Exception {
		String modelName = blockModelService.getActiveBlockModelName();
		CodeBlockModel model =
			blockModelService.getNewModelByName(modelName, program, true);
		TestGraphService graphService = new TestGraphService();
		BlockGraphTask task =
			new BlockGraphTask("test", false, DONT_SHOW_CODE, false, false,
				tool, null, null, model, graphService);

		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);

		AttributedGraph graph = display.getGraph();

		assertEquals(5, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex("01002200");
		AttributedVertex v2 = graph.getVertex("01002203");
		AttributedVertex v3 = graph.getVertex("01002239");
		AttributedVertex v4 = graph.getVertex("0100223c");
		AttributedVertex v5 = graph.getVertex("0100223e");

		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(v3);
		assertNotNull(v4);
		assertNotNull(v5);

		assertEquals(5, graph.getEdgeCount());
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v1, v3);
		AttributedEdge e3 = graph.getEdge(v3, v4);
		AttributedEdge e4 = graph.getEdge(v4, v5);
		AttributedEdge e5 = graph.getEdge(v3, v5);
		assertNotNull(e1);
		assertNotNull(e2);
		assertNotNull(e3);
		assertNotNull(e4);
		assertNotNull(e5);

		Map<String, String> map = v1.getAttributeMap();
		assertEquals(2, map.size());
		assertTrue(map.containsKey("Name"));
		assertTrue(map.containsKey("VertexType"));

		assertEquals("Entry", v3.getAttribute("VertexType"));
		assertEquals("Body", v4.getAttribute("VertexType"));
		assertEquals("Exit", v5.getAttribute("VertexType"));

		map = e1.getAttributeMap();
		assertEquals(2, map.size());
		assertTrue(map.containsKey("Name"));
		assertTrue(map.containsKey("EdgeType"));

		assertEquals("Fall-Through", e3.getAttribute("EdgeType"));
		assertEquals("Fall-Through", e4.getAttribute("EdgeType"));
		assertEquals("Conditional-Jump", e5.getAttribute("EdgeType"));
	}

	@Test
	public void testCodeBlockGraph() throws Exception {
		String modelName = blockModelService.getActiveBlockModelName();
		CodeBlockModel model =
			blockModelService.getNewModelByName(modelName, program, true);
		TestGraphService graphService = new TestGraphService();
		BlockGraphTask task =
			new BlockGraphTask("test", false, SHOW_CODE, false, false,
				tool, null, null, model, graphService);

		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);

		AttributedGraph graph = display.getGraph();

		assertEquals(5, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex("01002200");
		AttributedVertex v2 = graph.getVertex("01002203");
		AttributedVertex v3 = graph.getVertex("01002239");
		AttributedVertex v4 = graph.getVertex("0100223c");
		AttributedVertex v5 = graph.getVertex("0100223e");

		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(v3);
		assertNotNull(v4);
		assertNotNull(v5);

		assertEquals(5, graph.getEdgeCount());
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v1, v3);
		AttributedEdge e3 = graph.getEdge(v3, v4);
		AttributedEdge e4 = graph.getEdge(v4, v5);
		AttributedEdge e5 = graph.getEdge(v3, v5);
		assertNotNull(e1);
		assertNotNull(e2);
		assertNotNull(e3);
		assertNotNull(e4);
		assertNotNull(e5);

		Map<String, String> map = v3.getAttributeMap();
		assertEquals(4, map.size());
		assertTrue(map.containsKey("Name"));
		assertTrue(map.containsKey("VertexType"));
		assertTrue(map.containsKey("Code"));
		assertTrue(map.containsKey("Symbols"));

		assertEquals("simple", v3.getAttribute("Symbols"));
		assertEquals("nop   #0x1\nbreq  0x0100223e", v3.getAttribute("Code"));
	}

	@Test
	public void testCallGraph() throws Exception {
		String modelName = blockModelService.getActiveSubroutineModelName();
		CodeBlockModel model =
			blockModelService.getNewModelByName(modelName, program, true);
		TestGraphService graphService = new TestGraphService();
		BlockGraphTask task =
			new BlockGraphTask("test", false, false, false, false,
				tool, null, null, model, graphService);

		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);

		AttributedGraph graph = display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex("01002200");
		AttributedVertex v2 = graph.getVertex("01002239");

		assertNotNull(v1);
		assertNotNull(v2);

		assertEquals(1, graph.getEdgeCount());
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(e1);

		Map<String, String> map = v1.getAttributeMap();
		assertEquals(2, map.size());
		assertTrue(map.containsKey("Name"));
		assertTrue(map.containsKey("VertexType"));

		assertEquals("Entry", v1.getAttribute("VertexType"));
		assertEquals("Entry", v2.getAttribute("VertexType"));

		map = e1.getAttributeMap();

		assertEquals(2, map.size());
		assertTrue(map.containsKey("Name"));
		assertTrue(map.containsKey("EdgeType"));

		assertEquals("Unconditional-Call", e1.getAttribute("EdgeType"));

	}

	@Test
	public void testBlockGraphWithSelection() throws Exception {
		String modelName = blockModelService.getActiveBlockModelName();
		CodeBlockModel model =
			blockModelService.getNewModelByName(modelName, program, true);
		TestGraphService graphService = new TestGraphService();
		ProgramSelection sel = new ProgramSelection(addr(0x1002239), addr(0x1002247));
		BlockGraphTask task =
			new BlockGraphTask("test", false, DONT_SHOW_CODE, false, false,
				tool, sel, null, model, graphService);

		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);

		AttributedGraph graph = display.getGraph();

		assertEquals(3, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex("01002200");
		AttributedVertex v2 = graph.getVertex("01002203");
		AttributedVertex v3 = graph.getVertex("01002239");
		AttributedVertex v4 = graph.getVertex("0100223c");
		AttributedVertex v5 = graph.getVertex("0100223e");

		assertNull(v1);
		assertNull(v2);
		assertNotNull(v3);
		assertNotNull(v4);
		assertNotNull(v5);

		assertEquals(3, graph.getEdgeCount());
		AttributedEdge e3 = graph.getEdge(v3, v4);
		AttributedEdge e4 = graph.getEdge(v4, v5);
		AttributedEdge e5 = graph.getEdge(v3, v5);
		assertNotNull(e3);
		assertNotNull(e4);
		assertNotNull(e5);

	}

}
