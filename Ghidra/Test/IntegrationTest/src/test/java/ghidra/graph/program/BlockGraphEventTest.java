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

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.graph.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.util.task.TaskMonitor;

public class BlockGraphEventTest extends AbstractBlockGraphTest {

	private TestGraphDisplay display;
	private AttributedGraph graph;

	@Override
	public void setUp() throws Exception {
		super.setUp();
		String modelName = blockModelService.getActiveBlockModelName();
		CodeBlockModel model =
			blockModelService.getNewModelByName(modelName, program, true);
		TestGraphService graphService = new TestGraphService();
		BlockGraphTask task =
			new BlockGraphTask(new BlockFlowGraphType(), false, false, false,
				tool, null, null, model, graphService);

		task.monitoredRun(TaskMonitor.DUMMY);

		display = (TestGraphDisplay) graphService.getGraphDisplay(true, TaskMonitor.DUMMY);
		graph = display.getGraph();
	}

	@Test
	public void testGhidraLocationChanged() {
		codeBrowser.goTo(new ProgramLocation(program, addr(0x1002239)));
		assertEquals("01002239", display.getFocusedVertex().getId());
		codeBrowser.goTo(new ProgramLocation(program, addr(0x1002200)));
		assertEquals("01002200", display.getFocusedVertex().getId());

		// also try a location that is not the start of a block
		codeBrowser.goTo(new ProgramLocation(program, addr(0x100223a)));
		assertEquals("01002239", display.getFocusedVertex().getId());
	}

	private AddressSet addrSet(long start, long end) {
		return new AddressSet(addr(start), addr(end));
	}

	@Test
	public void testGhidraSelectionChanged() {
		setSelection(addrSet(0x1002239, 0x1002241));
		Set<AttributedVertex> selected = new HashSet<>(display.getSelectedVertices());
		assertEquals(3, selected.size());
		assertTrue(selected.contains(graph.getVertex("01002239")));
		assertTrue(selected.contains(graph.getVertex("0100223c")));
		assertTrue(selected.contains(graph.getVertex("0100223e")));

		setSelection(new AddressSet(addr(0x1002200), addr(0x1002210)));
		selected = new HashSet<>(display.getSelectedVertices());
		assertEquals(2, selected.size());
		assertTrue(selected.contains(graph.getVertex("01002200")));
		assertTrue(selected.contains(graph.getVertex("01002203")));

	}

	@Test
	public void testGraphNodeFocused() {
		display.focusChanged(graph.getVertex("01002203"));
		assertEquals(addr(0x01002203), codeBrowser.getCurrentLocation().getAddress());

		display.focusChanged(graph.getVertex("0100223c"));
		assertEquals(addr(0x0100223c), codeBrowser.getCurrentLocation().getAddress());

	}

	@Test
	public void testGraphNodesSelected() {
		display.selectionChanged(Set.of(graph.getVertex("01002239"), graph.getVertex("0100223c")));
		ProgramSelection selection = codeBrowser.getCurrentSelection();
		assertEquals(addr(0x01002239), selection.getMinAddress());
		assertEquals(addr(0x0100223d), selection.getMaxAddress());

		display.selectionChanged(Set.of(graph.getVertex("01002200"), graph.getVertex("01002203")));
		selection = codeBrowser.getCurrentSelection();
		assertEquals(addr(0x01002200), selection.getMinAddress());
		assertEquals(addr(0x01002204), selection.getMaxAddress());

	}

	private void setSelection(final AddressSet addrSet) {
		runSwing(
			() -> tool.firePluginEvent(
				new ProgramSelectionPluginEvent("test", new ProgramSelection(addrSet), program)),
			true);
	}
}
