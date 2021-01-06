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
package ghidra.app.plugin.core.debug.gui.time;

import org.junit.*;

import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.UndoableTransaction;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerTimePluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerTimePlugin timePlugin;
	DebuggerTimeProvider timeProvider;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		timePlugin = addPlugin(tool, DebuggerTimePlugin.class);
		timeProvider = waitForComponentProvider(DebuggerTimeProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerTimePlugin() throws Throwable {
		long fakeClock = (long) Integer.MAX_VALUE * 1000;
		TraceSnapshot snap;
		try (UndoableTransaction tid = tb.startTransaction()) {
			snap = tb.trace.getTimeManager().createSnapshot("Trace started");
			snap.setRealTime(fakeClock);

			TraceThread thread = tb.getOrAddThread("[1]", snap.getKey());

			snap = tb.trace.getTimeManager().createSnapshot("Thread STOPPED");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			fakeClock += 1000;

			snap = tb.trace.getTimeManager().createSnapshot("Thread BREAKPOINT_HIT");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			fakeClock += 2300;

			snap = tb.trace.getTimeManager().createSnapshot("Thread STEP_COMPLETED");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			snap.setSchedule(TraceSchedule.parse(snap.getKey() - 1 + ":1"));
			fakeClock += 444;

			snap = tb.trace.getTimeManager().createSnapshot("Thread STEP_COMPLETED");
			snap.setEventThread(thread);
			snap.setRealTime(fakeClock);
			snap.setSchedule(TraceSchedule.parse(snap.getKey() - 1 + ":1"));
			fakeClock += 100;
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(snap.getKey());

		captureIsolatedProvider(timeProvider, 600, 400);
	}
}
