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
package ghidra.app.plugin.core.debug.gui.register;

import java.math.BigInteger;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerRegistersPluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerRegistersPlugin registersPlugin;
	DebuggerRegistersProvider registersProvider;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		registersPlugin = addPlugin(tool, DebuggerRegistersPlugin.class);

		registersProvider = waitForComponentProvider(DebuggerRegistersProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerRegistersPlugin() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			long snap0 = tb.trace.getTimeManager().createSnapshot("First").getKey();
			long snap1 = tb.trace.getTimeManager().createSnapshot("Second").getKey();

			TraceThread thread = tb.getOrAddThread("[1]", snap0);
			TraceMemoryRegisterSpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			Language lang = tb.trace.getBaseLanguage();
			regs.setValue(snap0,
				new RegisterValue(lang.getRegister("RIP"), BigInteger.valueOf(0x00401234)));
			regs.setValue(snap0,
				new RegisterValue(lang.getRegister("RSP"), BigInteger.valueOf(0x7f104321)));
			regs.setValue(snap0,
				new RegisterValue(lang.getRegister("RAX"), BigInteger.valueOf(0x00000000)));
			regs.setValue(snap0,
				new RegisterValue(lang.getRegister("RBX"), BigInteger.valueOf(0x0)));
			regs.setValue(snap0,
				new RegisterValue(lang.getRegister("RCX"), BigInteger.valueOf(5)));
			regs.setValue(snap0,
				new RegisterValue(lang.getRegister("RDX"), BigInteger.valueOf(0x80)));

			regs.setValue(snap1,
				new RegisterValue(lang.getRegister("RIP"), BigInteger.valueOf(0x00401234)));
			regs.setValue(snap1,
				new RegisterValue(lang.getRegister("RSP"), BigInteger.valueOf(0x7f104321)));
			regs.setValue(snap1,
				new RegisterValue(lang.getRegister("RAX"), BigInteger.valueOf(0x00000000)));
			regs.setValue(snap1,
				new RegisterValue(lang.getRegister("RBX"), BigInteger.valueOf(0x7f104210)));
			regs.setValue(snap1,
				new RegisterValue(lang.getRegister("RCX"), BigInteger.valueOf(5)));
			regs.setValue(snap1,
				new RegisterValue(lang.getRegister("RDX"), BigInteger.valueOf(0x80)));

			tb.trace.getCodeManager()
					.getCodeRegisterSpace(thread, true)
					.definedData()
					.create(Range.atLeast(snap0), lang.getRegister("RIP"),
						PointerDataType.dataType);

			traceManager.openTrace(tb.trace);
			traceManager.activateThread(thread);
			traceManager.activateSnap(1);

			captureIsolatedProvider(registersProvider, 600, 600);
		}
	}

	@Test
	public void testCaptureDebuggerAvailableRegistersDialog() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			long snap0 = tb.trace.getTimeManager().createSnapshot("First").getKey();
			TraceThread thread = tb.getOrAddThread("[1]", snap0);

			traceManager.openTrace(tb.trace);
			traceManager.activateThread(thread);

			performAction(registersProvider.actionSelectRegisters, false);
			captureDialog(DebuggerAvailableRegistersDialog.class);
		}
	}
}
