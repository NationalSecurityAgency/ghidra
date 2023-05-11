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

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimeSelectionDialog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Swing;

public class DebuggerTraceViewDiffPluginTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected DebuggerTraceViewDiffPlugin traceDiffPlugin;
	protected DebuggerListingPlugin listingPlugin;

	protected DebuggerListingProvider listingProvider;

	@Before
	public void setUpTraceViewDiffPluginTest() throws Exception {
		traceDiffPlugin = addPlugin(tool, DebuggerTraceViewDiffPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);

		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);
	}

	@Test
	public void testActionCompareConfirm() throws Exception {
		assertFalse(traceDiffPlugin.actionCompare.isEnabled());
		assertNull(listingPlugin.getProvider().getOtherPanel());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(traceDiffPlugin.actionCompare.isEnabled());
		performAction(traceDiffPlugin.actionCompare, false);

		DebuggerTimeSelectionDialog dialog =
			waitForDialogComponent(DebuggerTimeSelectionDialog.class);
		Swing.runNow(() -> {
			dialog.setScheduleText("0");
			dialog.okCallback();
		});
		waitForSwing();

		assertNotNull(listingPlugin.getProvider().getOtherPanel());
	}

	@Test
	public void testActionCompareCancel() throws Exception {
		assertFalse(traceDiffPlugin.actionCompare.isEnabled());
		assertNull(listingPlugin.getProvider().getOtherPanel());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(traceDiffPlugin.actionCompare.isEnabled());
		performAction(traceDiffPlugin.actionCompare, false);

		DebuggerTimeSelectionDialog dialog =
			waitForDialogComponent(DebuggerTimeSelectionDialog.class);
		Swing.runNow(() -> {
			dialog.setScheduleText("0");
			dialog.cancelCallback();
		});
		waitForSwing();

		assertNull(listingPlugin.getProvider().getOtherPanel());
	}

	// TODO: Test schedule input validation?
	// TODO: Test stepping buttons?

	@Test
	public void testActionCompareClosesWhenAlreadyActive() throws Exception {
		assertFalse(traceDiffPlugin.actionCompare.isEnabled());
		assertNull(listingPlugin.getProvider().getOtherPanel());

		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(traceDiffPlugin.actionCompare.isEnabled());
		performAction(traceDiffPlugin.actionCompare, false);

		DebuggerTimeSelectionDialog dialog =
			waitForDialogComponent(DebuggerTimeSelectionDialog.class);
		Swing.runNow(() -> {
			dialog.setScheduleText("0");
			dialog.okCallback();
		});
		waitForSwing();

		assertNotNull(listingPlugin.getProvider().getOtherPanel());

		assertTrue(traceDiffPlugin.actionCompare.isEnabled());
		performAction(traceDiffPlugin.actionCompare, false);
		assertNull(listingPlugin.getProvider().getOtherPanel());
	}

	@Test
	public void testColorsDiffBytes() throws Throwable {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion(".text", 0, tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			ByteBuffer buf = ByteBuffer.allocate(0x1000); // Yes, smaller than .text
			buf.limit(0x1000);
			mm.putBytes(0, tb.addr(0x00400000), buf);
			buf.position(0);
			buf.putLong(0x0123, 0x1122334455667788L);
			mm.putBytes(1, tb.addr(0x00400000), buf);
		}
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		waitOn(traceDiffPlugin.startComparison(TraceSchedule.snap(1)));

		assertListingBackgroundAt(DebuggerTraceViewDiffPlugin.COLOR_DIFF,
			traceDiffPlugin.altListingPanel, tb.addr(0x00400123), 0);
		assertListingBackgroundAt(DebuggerTraceViewDiffPlugin.COLOR_DIFF,
			listingProvider.getListingPanel(), tb.addr(0x00400123), 0);

		AddressSetView expected = tb.set(tb.range(0x00400123, 0x0040012a));
		assertEquals(expected, Swing.runNow(() -> traceDiffPlugin.diffMarkersL.getAddressSet()));
		assertEquals(expected, Swing.runNow(() -> traceDiffPlugin.diffMarkersR.getAddressSet()));

		Swing.runNow(() -> traceDiffPlugin.endComparison());

		assertTrue(Swing.runNow(() -> traceDiffPlugin.diffMarkersL.getAddressSet()).isEmpty());
		assertTrue(Swing.runNow(() -> traceDiffPlugin.diffMarkersR.getAddressSet()).isEmpty());
	}

	@Test
	public void testActionPrevDiff() throws Throwable {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion(".text", 0, tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			ByteBuffer buf = ByteBuffer.allocate(0x1000); // Yes, smaller than .text
			buf.limit(0x1000);
			mm.putBytes(0, tb.addr(0x00400000), buf);
			buf.position(0);
			buf.putLong(0x0123, 0x1122334455667788L);
			buf.putLong(0x0321, 0x1122334455667788L);
			mm.putBytes(1, tb.addr(0x00400000), buf);
		}
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		waitOn(traceDiffPlugin.startComparison(TraceSchedule.snap(1)));

		assertFalse(traceDiffPlugin.actionPrevDiff.isEnabled());
		goTo(listingProvider.getListingPanel(),
			new ProgramLocation(tb.trace.getProgramView(), tb.addr(0x00401000)));
		waitForSwing();

		assertTrue(traceDiffPlugin.actionPrevDiff.isEnabled());
		performAction(traceDiffPlugin.actionPrevDiff);
		assertEquals(tb.addr(0x00400328), traceDiffPlugin.getCurrentAddress());

		assertTrue(traceDiffPlugin.actionPrevDiff.isEnabled());
		performAction(traceDiffPlugin.actionPrevDiff);
		assertEquals(tb.addr(0x0040012a), traceDiffPlugin.getCurrentAddress());

		assertFalse(traceDiffPlugin.actionPrevDiff.isEnabled());
	}

	@Test
	public void testActionNextDiff() throws Throwable {
		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion(".text", 0, tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			ByteBuffer buf = ByteBuffer.allocate(0x1000); // Yes, smaller than .text
			buf.limit(0x1000);
			mm.putBytes(0, tb.addr(0x00400000), buf);
			buf.position(0);
			buf.putLong(0x0123, 0x1122334455667788L);
			buf.putLong(0x0321, 0x1122334455667788L);
			mm.putBytes(1, tb.addr(0x00400000), buf);
		}
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		waitOn(traceDiffPlugin.startComparison(TraceSchedule.snap(1)));

		assertTrue(traceDiffPlugin.actionNextDiff.isEnabled());
		performAction(traceDiffPlugin.actionNextDiff);
		waitForPass(() -> assertEquals(tb.addr(0x00400123), traceDiffPlugin.getCurrentAddress()));

		assertTrue(traceDiffPlugin.actionNextDiff.isEnabled());
		performAction(traceDiffPlugin.actionNextDiff);
		assertEquals(tb.addr(0x00400321), traceDiffPlugin.getCurrentAddress());

		assertFalse(traceDiffPlugin.actionNextDiff.isEnabled());
	}
}
