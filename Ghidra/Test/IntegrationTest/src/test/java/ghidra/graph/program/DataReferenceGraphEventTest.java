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

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import ghidra.graph.TestGraphDisplay;
import ghidra.graph.TestGraphService;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.AttributedVertex;
import ghidra.util.task.TaskMonitor;

public class DataReferenceGraphEventTest extends AbstractDataReferenceGraphTest {

	private TestGraphDisplay display;
	private DataReferenceGraph graph;

	@Override
	public void setUp() throws Exception {
		super.setUp();
		TestGraphService graphService = new TestGraphService();
		ProgramLocation location = new ProgramLocation(program, addr(0x01000000));

		//	env.showTool(program);

		DataReferenceGraphTask task = new DataReferenceGraphTask(false, false, tool, null, location,
			graphService, 0, 10, DataReferenceGraph.Directions.BOTH_WAYS);

		task.monitoredRun(TaskMonitor.DUMMY);

		display = (TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		DataReferenceGraph otherGraph = new DataReferenceGraph(program, 0);
		otherGraph.graphFrom(addr(0x0100001d), DataReferenceGraph.Directions.BOTH_WAYS,
			TaskMonitor.DUMMY);
		display.setGraph(otherGraph, "testing", true, TaskMonitor.DUMMY);
		graph = (DataReferenceGraph) display.getGraph();
	}

	@Test
	public void testGhidraLocationChanged() {
		codeBrowser.goTo(new ProgramLocation(program, addr(0x01002200)));
		assertEquals("01002200",
			display.getFocusedVertex().getAttribute(DataReferenceGraph.ADDRESS_ATTRIBUTE));

		codeBrowser.goTo(new ProgramLocation(program, addr(0x1000000)));
		assertEquals("01000000",
			display.getFocusedVertex().getAttribute(DataReferenceGraph.ADDRESS_ATTRIBUTE));

		// also try a location that is not the start of a block
		codeBrowser.goTo(new ProgramLocation(program, addr(0x1000021)));
		assertEquals("0100001d",
			display.getFocusedVertex().getAttribute(DataReferenceGraph.ADDRESS_ATTRIBUTE));
	}

	@Test
	public void testGhidraSelectionChanged() {
		makeSelection(tool, program, addrSet(0x1000000, 0x100001c));
		Set<AttributedVertex> selected = new HashSet<>(display.getSelectedVertices());
		assertEquals(3, selected.size());
		assertTrue(selected.contains(graph.getVertex(graph.makeName(addr("01000000")))));
		assertTrue(selected.contains(graph.getVertex(graph.makeName(addr("0100000c")))));
		assertTrue(selected.contains(graph.getVertex(graph.makeName(addr("0100000f")))));

		makeSelection(tool, program, new AddressSet(addr(0x100000f), addr(0x1000021)));
		selected = new HashSet<>(display.getSelectedVertices());
		assertEquals(2, selected.size());
		assertTrue(selected.contains(graph.getVertex(graph.makeName(addr("0100000f")))));
		assertTrue(selected.contains(graph.getVertex(graph.makeName(addr("01000021")))));

	}

	@Test
	public void testGraphNodeFocused() {
		display.focusChanged(graph.getVertex(graph.makeName(addr(0x01002200))));
		assertEquals(addr(0x01002200), codeBrowser.getCurrentLocation().getAddress());

		display.focusChanged(graph.getVertex(graph.makeName(addr("01000000"))));
		assertEquals(addr(0x01000000), codeBrowser.getCurrentLocation().getAddress());

	}

	@Test
	public void testGraphNodesSelected() {
		display.selectionChanged(Set.of(graph.getVertex(graph.makeName(addr("01000000"))),
			graph.getVertex(graph.makeName(addr("0100000c")))));
		ProgramSelection selection = codeBrowser.getCurrentSelection();
		assertEquals(addr(0x01000000), selection.getMinAddress());
		assertEquals(addr(0x0100000c), selection.getMaxAddress());

		display.selectionChanged(Set.of(graph.getVertex(graph.makeName(addr("0100000f"))),
			graph.getVertex(graph.makeName(addr("01000021")))));
		selection = codeBrowser.getCurrentSelection();
		assertEquals(addr(0x0100000f), selection.getMinAddress());
		assertEquals(addr(0x01000024), selection.getMaxAddress());
	}
}
