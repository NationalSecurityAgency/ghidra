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
package ghidra.app.plugin.core.debug.gui.watch;

import org.junit.*;

import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerWatchesPluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerWatchesPlugin watchesPlugin;
	DebuggerWatchesProvider watchesProvider;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMin() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		watchesPlugin = addPlugin(tool, DebuggerWatchesPlugin.class);

		watchesProvider = waitForComponentProvider(DebuggerWatchesProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerWatchesPlugin() throws Throwable {
		TraceThread thread;
		long snap0, snap1;
		try (UndoableTransaction tid = tb.startTransaction()) {
			snap0 = tb.trace.getTimeManager().createSnapshot("First").getKey();
			snap1 = tb.trace.getTimeManager().createSnapshot("Second").getKey();

			thread = tb.getOrAddThread("[1]", snap0);

			PcodeExecutor<byte[]> executor0 =
				TraceSleighUtils.buildByteExecutor(tb.trace, snap0, thread, 0);
			executor0.executeLine("RSP = 0x7ffefff8");
			executor0.executeLine("*:4 (RSP+8) = 0x4030201");

			PcodeExecutor<byte[]> executor1 =
				TraceSleighUtils.buildByteExecutor(tb.trace, snap1, thread, 0);
			executor1.executeLine("RSP = 0x7ffefff8");
			executor1.executeLine("*:4 (RSP+8) = 0x1020304");
			executor1.executeLine("*:4 0x7fff0004:8 = 0x4A9A70C8");
		}

		watchesProvider.addWatch("RSP");
		watchesProvider.addWatch("*:8 RSP");
		watchesProvider.addWatch("*:4 (RSP+8)").setDataType(LongDataType.dataType);
		watchesProvider.addWatch("*:4 0x7fff0004:8").setDataType(FloatDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();
		traceManager.activateSnap(snap0);
		waitForSwing();
		traceManager.activateSnap(snap1);
		waitForSwing();

		captureIsolatedProvider(watchesProvider, 700, 400);
	}
}
