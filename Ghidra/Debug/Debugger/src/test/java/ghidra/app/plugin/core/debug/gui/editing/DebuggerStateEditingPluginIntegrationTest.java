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
package ghidra.app.plugin.core.debug.gui.editing;

import static org.junit.Assert.*;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Set;

import org.junit.Test;

import com.google.common.collect.Range;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.dnd.GClipboard;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.assembler.AssemblerPlugin;
import ghidra.app.plugin.core.assembler.AssemblerPluginTestHelper;
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPlugin;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPluginTestHelper;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.services.DebuggerStateEditingService;
import ghidra.app.services.DebuggerStateEditingService.StateEditingMode;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.util.Swing;
import ghidra.util.database.UndoableTransaction;

/**
 * Tests for editing machine state that don't naturally fit elsewhere.
 * 
 * <p>
 * In these and other machine-state-editing integration tests, we use
 * {@link StateEditingMode#WRITE_EMULATOR} as a stand-in for any mode. We also use
 * {@link StateEditingMode#READ_ONLY} just to verify the mode is heeded. Other modes may be tested
 * if bugs crop up in various combinations.
 */
public class DebuggerStateEditingPluginIntegrationTest extends AbstractGhidraHeadedDebuggerGUITest {
	@Test
	public void testPatchInstructionActionInDynamicListingEmu() throws Throwable {
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerDisassemblerPlugin disassemblerPlugin =
			addPlugin(tool, DebuggerDisassemblerPlugin.class);
		DebuggerStateEditingPlugin editingPlugin =
			addPlugin(tool, DebuggerStateEditingPlugin.class);
		DebuggerStateEditingService editingService =
			tool.getService(DebuggerStateEditingService.class);

		assertFalse(editingPlugin.actionEditMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			// Dynamic Patch Instruction requires existing code unit for context
			tb.addInstruction(0, tb.addr(0x00400123), tb.host);
		}

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		DebuggerDisassemblerPluginTestHelper helper =
			new DebuggerDisassemblerPluginTestHelper(disassemblerPlugin, listingProvider, view);

		traceManager.activateTrace(tb.trace);
		Swing.runNow(
			() -> listingProvider.goTo(view, new ProgramLocation(view, tb.addr(0x00400123))));
		waitForSwing();

		assertTrue(editingPlugin.actionEditMode.isEnabled());

		runSwing(() -> editingPlugin.actionEditMode
				.setCurrentActionStateByUserData(StateEditingMode.READ_ONLY));
		assertEquals(StateEditingMode.READ_ONLY, editingService.getCurrentMode(tb.trace));
		assertFalse(
			helper.patchInstructionAction.isAddToPopup(listingProvider.getActionContext(null)));

		runSwing(() -> editingPlugin.actionEditMode
				.setCurrentActionStateByUserData(StateEditingMode.WRITE_EMULATOR));
		assertEquals(StateEditingMode.WRITE_EMULATOR, editingService.getCurrentMode(tb.trace));

		assertTrue(
			helper.patchInstructionAction.isAddToPopup(listingProvider.getActionContext(null)));
		Instruction ins =
			helper.patchInstructionAt(tb.addr(0x00400123), "imm r0,#0x0", "imm r0,#1234");
		assertEquals(2, ins.getLength());

		long snap = traceManager.getCurrent().getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));
		byte[] bytes = new byte[2];
		view.getMemory().getBytes(tb.addr(0x00400123), bytes);
		assertArrayEquals(tb.arr(0x40, 1234), bytes);
	}

	@Test
	public void testPatchDataActionInDynamicListingEmu() throws Throwable {
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		AssemblerPlugin assemblerPlugin = addPlugin(tool, AssemblerPlugin.class);
		DebuggerStateEditingPlugin editingPlugin =
			addPlugin(tool, DebuggerStateEditingPlugin.class);
		DebuggerStateEditingService editingService =
			tool.getService(DebuggerStateEditingService.class);

		assertFalse(editingPlugin.actionEditMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			tb.trace.getCodeManager()
					.definedData()
					.create(Range.atLeast(0L), tb.addr(0x00400123), ShortDataType.dataType);
		}

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		AssemblerPluginTestHelper helper =
			new AssemblerPluginTestHelper(assemblerPlugin, listingProvider, view);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(editingPlugin.actionEditMode.isEnabled());

		runSwing(() -> editingPlugin.actionEditMode
				.setCurrentActionStateByUserData(StateEditingMode.READ_ONLY));
		assertEquals(StateEditingMode.READ_ONLY, editingService.getCurrentMode(tb.trace));
		assertFalse(helper.patchDataAction.isAddToPopup(listingProvider.getActionContext(null)));

		runSwing(() -> editingPlugin.actionEditMode
				.setCurrentActionStateByUserData(StateEditingMode.WRITE_EMULATOR));
		assertEquals(StateEditingMode.WRITE_EMULATOR, editingService.getCurrentMode(tb.trace));

		goTo(listingProvider.getListingPanel(), new ProgramLocation(view, tb.addr(0x00400123)));
		assertTrue(helper.patchDataAction.isAddToPopup(listingProvider.getActionContext(null)));

		/**
		 * TODO: There's a bug in the trace forking: Data units are not replaced when bytes changed.
		 * Thus, we'll make no assertions about the data unit.
		 */
		/*Data data =*/ helper.patchDataAt(tb.addr(0x00400123), "0h", "5h");
		// assertEquals(2, data.getLength());

		long snap = traceManager.getCurrent().getViewSnap();
		assertTrue(DBTraceUtils.isScratch(snap));
		byte[] bytes = new byte[2];
		view.getMemory().getBytes(tb.addr(0x00400123), bytes);
		assertArrayEquals(tb.arr(0, 5), bytes);
	}

	@Test
	public void testPasteActionInDynamicListingEmu() throws Throwable {
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerStateEditingPlugin editingPlugin =
			addPlugin(tool, DebuggerStateEditingPlugin.class);
		addPlugin(tool, ClipboardPlugin.class);
		DebuggerStateEditingService editingService =
			tool.getService(DebuggerStateEditingService.class);

		CodeViewerProvider listingProvider = listingPlugin.getProvider();
		DockingActionIf pasteAction = getLocalAction(listingProvider, "Paste");

		assertFalse(editingPlugin.actionEditMode.isEnabled());

		createAndOpenTrace();
		TraceVariableSnapProgramView view = tb.trace.getProgramView();
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin:.text]", 0, tb.range(0x00400000, 0x00401000),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
		}

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		ActionContext ctx;

		assertTrue(editingPlugin.actionEditMode.isEnabled());

		runSwing(() -> editingPlugin.actionEditMode
				.setCurrentActionStateByUserData(StateEditingMode.READ_ONLY));
		assertEquals(StateEditingMode.READ_ONLY, editingService.getCurrentMode(tb.trace));
		ctx = listingProvider.getActionContext(null);
		assertTrue(pasteAction.isAddToPopup(ctx));
		assertFalse(pasteAction.isEnabledForContext(ctx));

		runSwing(() -> editingPlugin.actionEditMode
				.setCurrentActionStateByUserData(StateEditingMode.WRITE_EMULATOR));
		assertEquals(StateEditingMode.WRITE_EMULATOR, editingService.getCurrentMode(tb.trace));

		goTo(listingPlugin.getListingPanel(), new ProgramLocation(view, tb.addr(0x00400123)));
		ctx = listingProvider.getActionContext(null);
		assertTrue(pasteAction.isAddToPopup(ctx));
		assertFalse(pasteAction.isEnabledForContext(ctx));

		Clipboard clipboard = GClipboard.getSystemClipboard();
		clipboard.setContents(new StringSelection("12 34 56 78"), null);
		ctx = listingProvider.getActionContext(null);
		assertTrue(pasteAction.isAddToPopup(ctx));
		assertTrue(pasteAction.isEnabledForContext(ctx));

		performAction(pasteAction, listingProvider, false);
		OptionDialog confirm = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(confirm, "Yes");

		byte[] bytes = new byte[4];
		waitForPass(noExc(() -> {
			long snap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(snap));
			view.getMemory().getBytes(tb.addr(0x00400123), bytes);
			assertArrayEquals(tb.arr(0x12, 0x34, 0x56, 0x78), bytes);
		}));
	}
}
