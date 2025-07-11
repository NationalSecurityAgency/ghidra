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
package ghidra.app.plugin.core.debug.gui.pcode;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerPcodeStepperPluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerPcodeStepperPlugin pcodePlugin;
	DebuggerPcodeStepperProvider pcodeProvider;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		pcodePlugin = addPlugin(tool, DebuggerPcodeStepperPlugin.class);

		pcodeProvider = waitForComponentProvider(DebuggerPcodeStepperProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerPcodeStepperPlugin() throws Throwable {
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);
			long snap0 = tb.trace.getTimeManager().createSnapshot("First").getKey();

			tb.trace.getMemoryManager()
					.addRegion("Memory[echo:.text]", Lifespan.nowOn(snap0),
						tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ,
						TraceMemoryFlag.EXECUTE);

			TraceThread thread = tb.getOrAddThread("Threads[1]", snap0);
			tb.trace.getObjectManager()
					.createObject(thread.getObject().getCanonicalPath().key("Registers"));

			PcodeExecutor<byte[]> exe =
				TraceSleighUtils.buildByteExecutor(tb.trace, snap0, thread, 0);
			exe.executeSleigh("""
					RIP = 0x00400000;
					RSP = 0x0010fff8;
					""");

			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(snap0));
			asm.assemble(tb.addr(0x00400000), "SUB RSP,0x40");

			traceManager.openTrace(tb.trace);
			traceManager.activateThread(thread);
			traceManager.activateTime(TraceSchedule.snap(0).steppedPcodeForward(thread, 7));
			waitForSwing();

			runSwing(() -> pcodeProvider.mainPanel.setDividerLocation(360));
			captureIsolatedProvider(pcodeProvider, 900, 300);
		}
	}
}
