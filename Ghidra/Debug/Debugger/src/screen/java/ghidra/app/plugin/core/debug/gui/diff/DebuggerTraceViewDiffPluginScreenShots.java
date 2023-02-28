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
package ghidra.app.plugin.core.debug.gui.diff;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimeSelectionDialog;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.async.AsyncTestUtils;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Swing;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerTraceViewDiffPluginScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {

	DebuggerTraceManagerService traceManager;
	DebuggerTraceViewDiffPlugin diffPlugin;
	DebuggerListingPlugin listingPlugin;
	DebuggerListingProvider listingProvider;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		diffPlugin = addPlugin(tool, DebuggerTraceViewDiffPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);

		tb = new ToyDBTraceBuilder("tictactoe", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerTraceViewDiffPlugin() throws Throwable {
		long snap1, snap2;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceTimeManager tm = tb.trace.getTimeManager();
			snap1 = tm.createSnapshot("Baseline").getKey();
			snap2 = tm.createSnapshot("X's first move").getKey();
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion(".data", snap1, tb.range(0x00600000, 0x0060ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);

			ByteBuffer buf = ByteBuffer.allocate(0x1000).order(ByteOrder.LITTLE_ENDIAN);
			buf.put((byte) 'X');
			buf.putInt(3);
			buf.putInt(3);
			for (int i = 0; i < 9; i++) {
				buf.put((byte) ' ');
			}
			buf.flip();
			buf.limit(0x1000);
			mm.putBytes(snap1, tb.addr(0x00600000), buf);

			buf.put(0, (byte) 'O');
			buf.put(13, (byte) 'X');
			buf.position(0);
			buf.limit(0x1000);
			mm.putBytes(snap2, tb.addr(0x00600000), buf);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(snap1);
		waitForSwing();

		waitOn(diffPlugin.startComparison(TraceSchedule.snap(snap2)));
		assertTrue(diffPlugin.gotoNextDiff());

		captureIsolatedProvider(DebuggerListingProvider.class, 900, 600);
	}

	@Test
	public void testCaptureDebuggerTimeSelectionDialog() throws Throwable {
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceTimeManager tm = tb.trace.getTimeManager();
			thread = tb.getOrAddThread("main", 0);
			tm.createSnapshot("Break on main").setEventThread(thread);
			tm.createSnapshot("Game started").setEventThread(thread);
			tm.createSnapshot("X's moved").setEventThread(thread);
			tm.createSnapshot("O's moved").setEventThread(thread);
		}
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		performAction(diffPlugin.actionCompare, false);
		DebuggerTimeSelectionDialog dialog =
			waitForDialogComponent(DebuggerTimeSelectionDialog.class);
		Swing.runNow(() -> dialog.setScheduleText("2"));

		captureDialog(dialog);
	}
}
