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
package ghidra.app.plugin.core.debug.gui;

import java.io.IOException;

import org.junit.*;

import ghidra.app.plugin.core.bookmark.BookmarkPlugin;
import ghidra.app.plugin.core.byteviewer.ByteViewerPlugin;
import ghidra.app.plugin.core.clear.ClearPlugin;
import ghidra.app.plugin.core.comments.CommentsPlugin;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointMarkerPlugin;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPlugin;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin;
import ghidra.app.plugin.core.debug.gui.target.DebuggerTargetsPlugin;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPlugin;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin;
import ghidra.app.plugin.core.debug.service.workflow.DebuggerWorkflowServiceProxyPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.plugin.core.equate.EquatePlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.label.LabelMgrPlugin;
import ghidra.app.plugin.core.symtable.SymbolTablePlugin;
import ghidra.app.plugin.debug.MemoryUsagePlugin;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.language.DBTraceGuestLanguage;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;

public class DebuggerManualTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected ToyDBTraceBuilder ub;

	@Before
	public void setUpManualTest() throws IOException {
		createTrace();
		ub = new ToyDBTraceBuilder("dynamic2-" + name.getMethodName(), LANGID_TOYBE64);
		try (UndoableTransaction tid = ub.startTransaction()) {
			ub.trace.getTimeManager().createSnapshot("First snap");
		}
	}

	@After
	public void tearDownManualTest() {
		if (ub != null) {
			if (traceManager != null && traceManager.getOpenTraces().contains(ub.trace)) {
				traceManager.closeTrace(ub.trace);
			}
			ub.close();
		}
	}

	@Test
	@Ignore
	public void testManual01() throws PluginException, CodeUnitInsertionException,
			DataTypeConflictException, AddressOverflowException, DuplicateNameException,
			TraceOverlappedRegionException, InterruptedException {
		addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);

		addPlugin(tool, DebuggerBreakpointsPlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, DebuggerModulesPlugin.class);
		addPlugin(tool, DebuggerRegistersPlugin.class);
		//addPlugin(tool, DebuggerRegsListingPlugin.class);
		addPlugin(tool, DebuggerTargetsPlugin.class);
		addPlugin(tool, DebuggerThreadsPlugin.class);
		addPlugin(tool, DebuggerTimePlugin.class);
		addPlugin(tool, DebuggerWorkflowServiceProxyPlugin.class);

		//addPlugin(tool, AssemblerPlugin.class);
		addPlugin(tool, ByteViewerPlugin.class);
		addPlugin(tool, BookmarkPlugin.class);
		addPlugin(tool, ClearPlugin.class);
		addPlugin(tool, CommentsPlugin.class);
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DataPlugin.class);
		//addPlugin(tool, DecompilePlugin.class);
		addPlugin(tool, EquatePlugin.class);
		//addPlugin(tool, FallThroughPlugin.class);
		//addPlugin(tool, FindPossibleReferencesPlugin.class);
		//addPlugin(tool, FlowArrowPlugin.class);
		//addPlugin(tool, FunctionNameListingHoverPlugin.class);
		addPlugin(tool, FunctionPlugin.class);
		//addPlugin(tool, FunctionSignatureDecompilerHoverPlugin.class);
		//addPlugin(tool, InterpreterPanelPlugin.class);
		//addPlugin(tool, GoToAddressLabelPlugin.class);
		addPlugin(tool, LabelMgrPlugin.class);
		//addPlugin(tool, LocationReferencesPlugin.class);
		//addPlugin(tool, MarkerManagerPlugin.class);
		addPlugin(tool, MemoryUsagePlugin.class);
		//addPlugin(tool, MemSearchPlugin.class);
		//addPlugin(tool, MnemonicSearchPlugin.class);
		//addPlugin(tool, NextPrevAddressPlugin.class);
		//addPlugin(tool, NextPrevCodeUnitPlugin.class);
		//addPlugin(tool, NextPrevHighlightRangePlugin.class);
		//addPlugin(tool, NextPrevSelectedRangePlugin.class);
		addPlugin(tool, SymbolTablePlugin.class);

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion("Region", 0, tb.range(0x4000, 0x4fff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			tb.trace.getThreadManager().createThread("Thread 1", 0);
			tb.trace.getThreadManager().createThread("Thread 2", 4);

			tb.addData(0, tb.addr(0x4004), Undefined4DataType.dataType, tb.buf(6, 7, 8, 9));
			tb.addInstruction(0, tb.addr(0x4008), tb.language, tb.buf(0xf4, 0));

			Language x86 = getSLEIGH_X86_LANGUAGE();
			DBTraceGuestLanguage guest = tb.trace.getLanguageManager().addGuestLanguage(x86);
			guest.addMappedRange(tb.addr(0x4000), tb.addr(guest, 0x00400000), 0x1000);
			tb.addInstruction(0, tb.addr(0x400a), x86, tb.buf(0x90));
		}
		waitForSwing();

		traceManager.openTrace(tb.trace);
		traceManager.openTrace(ub.trace);
		traceManager.activateTrace(tb.trace);

		waitFor(() -> tool.isVisible());
		while (tool.isVisible()) {
			Thread.sleep(1000);
		}
	}
}
