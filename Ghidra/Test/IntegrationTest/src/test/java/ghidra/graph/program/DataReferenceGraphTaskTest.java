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

import org.junit.Test;

import ghidra.graph.TestGraphDisplay;
import ghidra.graph.TestGraphService;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

public class DataReferenceGraphTaskTest extends AbstractDataReferenceGraphTest {

	@Test
	public void testGraphWithLimit() throws GraphException {

		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100001d)), graphService, 1, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(e1);
	}

	@Test
	public void testGraphWithoutLimit() throws GraphException {

		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100001d)), graphService, 0, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(3, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedVertex v3 = graph.getVertex(graph.makeName(addr(0x0100000f)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v2, v3);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(v3);
		assertNotNull(e1);
		assertNotNull(e2);
	}

	@Test
	public void testGraphAdd() throws GraphException {
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100001d)), graphService, 1, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(e1);

		DataReferenceGraphTask taskAdd = new DataReferenceGraphTask(tool, program,
			addrSet(0x0100000c, 0x0100000c), display, 1, DataReferenceGraph.Directions.BOTH_WAYS);
		taskAdd.monitoredRun(TaskMonitor.DUMMY);
		graph = (DataReferenceGraph) display.getGraph();
		assertEquals(3, graph.getVertexCount());
		AttributedVertex v1Add = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2Add = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedVertex v3Add = graph.getVertex(graph.makeName(addr(0x0100000f)));
		AttributedEdge e1Add = graph.getEdge(v1Add, v2Add);
		AttributedEdge e2Add = graph.getEdge(v2Add, v3Add);
		assertNotNull(v1Add);
		assertNotNull(v2Add);
		assertNotNull(v3Add);
		assertNotNull(e1Add);
		assertNotNull(e2Add);
	}

	@Test
	public void testDirectionsBoth() throws GraphException {
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100000c)), graphService, 0, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(3, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedVertex v3 = graph.getVertex(graph.makeName(addr(0x0100000f)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v2, v3);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(v3);
		assertNotNull(e1);
		assertNotNull(e2);
	}

	@Test
	public void testDirectionsTo() throws GraphException {
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100000c)), graphService, 0, 10,
			DataReferenceGraph.Directions.TO_ONLY);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedVertex v3 = graph.getVertex(graph.makeName(addr(0x0100000f)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v2, v3);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNull(v3);
		assertNotNull(e1);
		assertNull(e2);
	}

	@Test
	public void testDirectionsFrom() throws GraphException {
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100000c)), graphService, 0, 10,
			DataReferenceGraph.Directions.FROM_ONLY);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedVertex v3 = graph.getVertex(graph.makeName(addr(0x0100000f)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v2, v3);
		assertNull(v1);
		assertNotNull(v2);
		assertNotNull(v3);
		assertNull(e1);
		assertNotNull(e2);
	}

	@Test
	public void testNodeWithType() throws GraphException {
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x0100001d)), graphService, 1, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		AttributedVertex vertex = graph.getVertex(graph.makeName(addr(0x0100001d)));
		assertEquals("pointer_thing", vertex.getAttribute(DataReferenceGraph.DATA_ATTRIBUTE));
		assertEquals("0100001d", vertex.getAttribute(DataReferenceGraph.ADDRESS_ATTRIBUTE));
		assertNull(vertex.getAttribute(DataReferenceGraph.LABEL_ATTRIBUTE)); // no label at address
	}

	@Test
	public void testCodeReference() throws GraphException {
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null,
			new ProgramLocation(program, addr(0x01002200)), graphService, 0, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		assertEquals(2, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x01002200)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x01000000)));
		AttributedEdge e1 = graph.getEdge(v1, v2);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(e1);
		assertEquals("Instruction", v1.getVertexType());
	}

	@Test
	public void testGraphSelection() throws GraphException {
		ProgramSelection selection = new ProgramSelection(addr(0x01000000), addr(0x0100000c));
		TestGraphService graphService = new TestGraphService();
		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, selection,
			new ProgramLocation(program, addr(0x0100000c)), graphService, 0, 10,
			DataReferenceGraph.Directions.BOTH_WAYS);
		task.monitoredRun(TaskMonitor.DUMMY);

		TestGraphDisplay display =
			(TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph graph = (DataReferenceGraph) display.getGraph();

		//there's an extra vertex at 0x0100000b as an artifact of selection construction
		assertEquals(6, graph.getVertexCount());
		AttributedVertex v1 = graph.getVertex(graph.makeName(addr(0x0100001d)));
		AttributedVertex v2 = graph.getVertex(graph.makeName(addr(0x0100000c)));
		AttributedVertex v3 = graph.getVertex(graph.makeName(addr(0x0100000f)));
		AttributedVertex v4 = graph.getVertex(graph.makeName(addr(0x01002200)));
		AttributedVertex v5 = graph.getVertex(graph.makeName(addr(0x01000000)));
		AttributedEdge e3 = graph.getEdge(v4, v5);
		AttributedEdge e1 = graph.getEdge(v1, v2);
		AttributedEdge e2 = graph.getEdge(v2, v3);
		assertNotNull(v1);
		assertNotNull(v2);
		assertNotNull(v3);
		assertNotNull(v4);
		assertNotNull(v5);
		assertNotNull(e1);
		assertNotNull(e2);
		assertNotNull(e3);
	}

}
