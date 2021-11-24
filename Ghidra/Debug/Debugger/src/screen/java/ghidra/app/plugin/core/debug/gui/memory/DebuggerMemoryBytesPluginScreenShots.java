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
package ghidra.app.plugin.core.debug.gui.memory;

import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerMemoryBytesPluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerMemoryBytesPlugin memoryPlugin;
	DebuggerMemoryBytesProvider memoryProvider;
	DebuggerListingPlugin listingPlugin; // For colors
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		memoryPlugin = addPlugin(tool, DebuggerMemoryBytesPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);

		memoryProvider = waitForComponentProvider(DebuggerMemoryBytesProvider.class);
		tool.showComponentProvider(memoryProvider, true);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerMemoryBytesPlugin() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			long snap = tb.trace.getTimeManager().createSnapshot("First").getKey();
			tb.trace.getMemoryManager()
					.addRegion(".text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			TraceSymbolManager symbolManager = tb.trace.getSymbolManager();
			TraceNamespaceSymbol global = symbolManager.getGlobalNamespace();

			TraceSymbol mainLabel = symbolManager
					.labels()
					.create(snap, null, tb.addr(0x00400000),
						"main", global, SourceType.USER_DEFINED);
			@SuppressWarnings("unused")
			TraceSymbol cloneLabel = symbolManager
					.labels()
					.create(snap, null, tb.addr(0x00400060),
						"clone", global, SourceType.USER_DEFINED);
			TraceSymbol childLabel = symbolManager
					.labels()
					.create(snap, null, tb.addr(0x00400034),
						"child", global, SourceType.USER_DEFINED);
			@SuppressWarnings("unused")
			TraceSymbol exitLabel = symbolManager
					.labels()
					.create(snap, null, tb.addr(0x00400061),
						"exit", global, SourceType.USER_DEFINED);

			Assembler assembler = Assemblers.getAssembler(tb.trace.getProgramView());

			assembler.assemble(mainLabel.getAddress(),
				"PUSH RBP",
				"MOV RBP,RSP",
				"CALL clone",
				"TEST EAX,EAX",
				"JNZ child",
				"SUB RSP,0x10",
				"MOV dword ptr [RSP],0x6c6c6548",
				"MOV dword ptr [RSP+4],0x57202c6f",
				"MOV dword ptr [RSP+8],0x646c726f",
				"MOV word ptr [RSP+0xc],0x21",
				"CALL exit",
				"SUB RSP,0x10",
				"MOV dword ptr [RSP],0x2c657942",
				"MOV dword ptr [RSP+4],0x726f5720",
				"MOV dword ptr [RSP+8],0x21646c",
				"CALL exit");

			TraceThread thread = tb.getOrAddThread("[1]", snap);

			TraceMemoryRegisterSpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regs.setValue(snap, new RegisterValue(tb.language.getProgramCounter(),
				childLabel.getAddress().getOffsetAsBigInteger()));
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		captureIsolatedProvider(DebuggerMemoryBytesProvider.class, 600, 600);
	}
}
