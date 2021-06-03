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
package ghidra.app.plugin.core.debug.gui.modules;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

public class DebuggerStaticMappingProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerStaticMappingPlugin mappingsPlugin;
	protected DebuggerStaticMappingProvider mappingsProvider;

	protected TraceStaticMappingManager manager;

	@Before
	public void setUpStaticMappingsProviderTest()
			throws LanguageNotFoundException, IOException, PluginException {
		mappingsPlugin = addPlugin(tool, DebuggerStaticMappingPlugin.class);
		mappingsProvider = waitForComponentProvider(DebuggerStaticMappingProvider.class);

		createTrace();
		manager = tb.trace.getStaticMappingManager();
	}

	@Test
	public void testActivateThenAddStaticMappingPopulatesProvider() throws Exception {
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef, 0xdeadbeef + 0xff), Range.atLeast(0L),
				new URL("ghidra://static"), "DEADBEEF");
		}
		waitForDomainObject(tb.trace);

		List<StaticMappingRow> displayed = mappingsProvider.mappingTableModel.getModelData();
		assertEquals(1, displayed.size());
		StaticMappingRow record = displayed.get(0);
		assertEquals(tb.addr(0xdeadbeef), record.getTraceAddress());
		assertEquals(new URL("ghidra://static"), record.getStaticProgramURL());
		assertEquals("DEADBEEF", record.getStaticAddress());
		assertEquals(0x100, record.getLength());
	}

	@Test
	public void testAddStaticMappingThenActivatePopulatesProvider() throws Exception {
		traceManager.openTrace(tb.trace);
		// Note: don't activate yet

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef, 0xdeadbeef + 0xff), Range.atLeast(0L),
				new URL("ghidra://static"), "DEADBEEF");
		}
		waitForDomainObject(tb.trace);

		// Verify the provider is not yet populated
		assertTrue(mappingsProvider.mappingTableModel.getModelData().isEmpty());

		// Activate and re-check
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		List<StaticMappingRow> displayed = mappingsProvider.mappingTableModel.getModelData();
		assertEquals(1, displayed.size());
		StaticMappingRow record = displayed.get(0);
		assertEquals(tb.addr(0xdeadbeef), record.getTraceAddress());
		assertEquals(new URL("ghidra://static"), record.getStaticProgramURL());
		assertEquals("DEADBEEF", record.getStaticAddress());
		assertEquals(0x100, record.getLength());
	}

	@Test
	public void testAddAction() throws Exception {
		assertTrue(mappingsProvider.actionAdd.isEnabled());

		createProgramFromTrace(tb.trace);
		intoProject(tb.trace);
		intoProject(program);

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion(".text", Range.atLeast(0L),
						tb.range(0xdeadbeefL, 0xdeadbeefL + 0xff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}
		waitForDomainObject(tb.trace);

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0xc0de1234L), 0x100, (byte) 0,
						TaskMonitor.DUMMY, false);
		}
		waitForDomainObject(program);

		CodeBrowserPlugin codeViewerPlugin = addPlugin(tool, CodeBrowserPlugin.class);
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		programManager.openProgram(program);
		waitForSwing();

		ProgramSelection traceSel =
			new ProgramSelection(tb.addr(0xdeadbeefL), tb.addr(0xdeadbeefL + 0x0f));
		listingPlugin.getProvider().setSelection(traceSel);
		codeViewerPlugin.goTo(new ProgramLocation(program, addr(program, 0xc0de1234L)), true);
		waitForSwing();

		performAction(mappingsProvider.actionAdd, false);

		DebuggerAddMappingDialog dialog = waitForDialogComponent(DebuggerAddMappingDialog.class);
		dialog.applyCallback();
		dialog.close();
		waitForDomainObject(tb.trace);

		TraceStaticMapping entry = Unique.assertOne(manager.getAllEntries());
		assertEquals(Range.atLeast(0L), entry.getLifespan());
		assertEquals(tb.range(0xdeadbeefL, 0xdeadbeefL + 0x0f), entry.getTraceAddressRange());
		assertEquals(ProgramURLUtils.getUrlFromProgram(program), entry.getStaticProgramURL());
		assertEquals("ram:c0de1234", entry.getStaticAddress());
	}

	@Test
	public void testRemoveActionRemovesFromProviderAndTrace() throws Exception {
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef, 0xdeadbeef + 0xff), Range.atLeast(0L),
				new URL("ghidra://static"), "DEADBEEF");
			manager.add(tb.range(0xdeadbeef + 0x100, 0xdeadbeef + 0x17f), Range.atLeast(0L),
				new URL("ghidra://static"), "C0DE1234");
			manager.add(tb.range(0xdeadbeef + 0x180, 0xdeadbeef + 0x1bf), Range.atLeast(0L),
				new URL("ghidra://static"), "1E55C0DE");
		}
		waitForDomainObject(tb.trace);

		// First check that all records are displayed
		waitForPass(() -> assertEquals(3, mappingsProvider.mappingTable.getRowCount()));
		List<StaticMappingRow> mappingsDisplayed =
			mappingsProvider.mappingTableModel.getModelData();
		assertEquals(3, mappingsDisplayed.size());

		// Select and remove the first 2 via the action
		// NOTE: I'm not responsible for making the transaction here. The UI should do it.
		mappingsProvider.mappingTable.getSelectionModel().setSelectionInterval(0, 1);
		performAction(mappingsProvider.actionRemove);
		waitForDomainObject(tb.trace);

		// Now, check that only the final one remains
		mappingsDisplayed = mappingsProvider.mappingTableModel.getModelData();
		assertEquals(1, mappingsDisplayed.size());
		StaticMappingRow record = mappingsDisplayed.get(0);
		assertEquals(tb.addr(0xdeadbeef + 0x180), record.getTraceAddress());

		// Check that they were removed from the trace as well
		Iterator<? extends TraceStaticMapping> it = manager.getAllEntries().iterator();
		assertTrue(it.hasNext());
		TraceStaticMapping entry = it.next();
		assertEquals(tb.addr(0xdeadbeef + 0x180), entry.getMinTraceAddress());
		assertFalse(it.hasNext());
	}

	@Test
	public void testRemoveViaTraceRemovesFromProvider() throws Exception {
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef, 0xdeadbeef + 0xff), Range.atLeast(0L),
				new URL("ghidra://static"), "DEADBEEF");
			manager.add(tb.range(0xdeadbeef + 0x100, 0xdeadbeef + 0x17f), Range.atLeast(0L),
				new URL("ghidra://static"), "C0DE1234");
			manager.add(tb.range(0xdeadbeef + 0x180, 0xdeadbeef + 0x1bf), Range.atLeast(0L),
				new URL("ghidra://static"), "1E55C0DE");
		}
		waitForDomainObject(tb.trace);

		// First check that all records are displayed
		List<StaticMappingRow> displayed = mappingsProvider.mappingTableModel.getModelData();
		assertEquals(3, displayed.size());

		// Remove the first two in another transaction
		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.findContaining(tb.addr(0xdeadbeef), 0).delete();
			manager.findContaining(tb.addr(0xdeadbeef + 0x100), 0).delete();
		}
		waitForDomainObject(tb.trace);

		// Now, check that only the final one remains
		displayed = mappingsProvider.mappingTableModel.getModelData();
		assertEquals(1, displayed.size());
		StaticMappingRow record = displayed.get(0);
		assertEquals(tb.addr(0xdeadbeef + 0x180), record.getTraceAddress());
	}

	@Test
	public void testUndoHonored() throws Exception {
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef, 0xdeadbeef + 0xff), Range.atLeast(0L),
				new URL("ghidra://static"), "DEADBEEF");
			manager.add(tb.range(0xdeadbeef + 0x100, 0xdeadbeef + 0x17f), Range.atLeast(0L),
				new URL("ghidra://static"), "C0DE1234");
		}

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef + 0x180, 0xdeadbeef + 0x1bf), Range.atLeast(0L),
				new URL("ghidra://static"), "1E55C0DE");
		}
		waitForDomainObject(tb.trace);

		// First check that all records are displayed
		assertEquals(3, mappingsProvider.mappingTableModel.getModelData().size());

		undo(tb.trace, true);

		// Check that only two are displayed
		assertEquals(2, mappingsProvider.mappingTableModel.getModelData().size());
	}

	@Test
	public void testAbortHonored() throws Exception {
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef, 0xdeadbeef + 0xff), Range.atLeast(0L),
				new URL("ghidra://static"), "DEADBEEF");
			manager.add(tb.range(0xdeadbeef + 0x100, 0xdeadbeef + 0x17f), Range.atLeast(0L),
				new URL("ghidra://static"), "C0DE1234");
		}

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.add(tb.range(0xdeadbeef + 0x180, 0xdeadbeef + 0x1bf), Range.atLeast(0L),
				new URL("ghidra://static"), "1E55C0DE");
			waitForDomainObject(tb.trace);

			// Check that all records are displayed in the interim
			assertEquals(3, mappingsProvider.mappingTableModel.getModelData().size());

			tid.abort();
		}
		waitForDomainObject(tb.trace);

		// Check that only two are displayed
		assertEquals(2, mappingsProvider.mappingTableModel.getModelData().size());
	}

	// TODO: Switching between traces

	// TODO: Switching to no trace (null)
}
