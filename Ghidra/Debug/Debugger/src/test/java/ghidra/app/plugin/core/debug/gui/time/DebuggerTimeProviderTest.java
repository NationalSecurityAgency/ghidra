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

import static org.junit.Assert.*;

import java.util.Calendar;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.trace.database.time.DBTraceSnapshot;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DebuggerTimeProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected DebuggerTimePlugin timePlugin;
	protected DebuggerTimeProvider timeProvider;

	@Before
	public void setUpTimeProviderTest() throws Exception {
		timePlugin = addPlugin(tool, DebuggerTimePlugin.class);
		timeProvider = waitForComponentProvider(DebuggerTimeProvider.class);
	}

	protected void addSnapshots() {
		DBTraceTimeManager timeManager = tb.trace.getTimeManager();
		try (Transaction tx = tb.startTransaction()) {
			TraceSnapshot first = timeManager.createSnapshot("First");
			Calendar c = Calendar.getInstance(); // System time zone
			c.set(2020, 0, 1, 9, 0, 0);
			first.setRealTime(c.getTimeInMillis());
			TraceSnapshot second = timeManager.getSnapshot(10, true);
			second.setDescription("Snap 10");
			second.setSchedule(TraceSchedule.parse("0:5;t1-5"));
		}
	}

	protected void addScratchSnapshot() {
		DBTraceTimeManager timeManager = tb.trace.getTimeManager();
		try (Transaction tx = tb.startTransaction()) {
			TraceSnapshot scratch = timeManager.getSnapshot(Long.MIN_VALUE, true);
			scratch.setDescription("Scratch");
			scratch.setSchedule(TraceSchedule.parse("0:t0-5"));
		}
	}

	protected void assertProviderEmpty() {
		assertTrue(timeProvider.mainPanel.snapshotTableModel.getModelData().isEmpty());
	}

	protected void assertProviderPopulated() {
		List<SnapshotRow> snapsDisplayed = timeProvider.mainPanel.snapshotTableModel.getModelData();
		// I should be able to assume this is sorted by key
		assertEquals(2, snapsDisplayed.size());

		SnapshotRow firstRow = snapsDisplayed.get(0);
		assertEquals(0, firstRow.getSnap());
		assertEquals("First", firstRow.getDescription());
		assertEquals("0", firstRow.getSchedule()); // Snap 0 has "0" schedule
		assertEquals("Jan 01, 2020 09:00 AM", firstRow.getTimeStamp());

		SnapshotRow secondRow = snapsDisplayed.get(1);
		assertEquals(10, secondRow.getSnap());
		assertEquals("Snap 10", secondRow.getDescription());
		assertEquals("0:5;t1-5", secondRow.getSchedule());
		// Timestamp is left unchecked, since default is current time
	}

	@Test // TODO: Technically, this is a plugin action.... Different test case?
	public void testActionRenameSnapshot() throws Exception {
		// More often than not, this action will be used from the dynamic listing
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listingProvider =
			waitForComponentProvider(DebuggerListingProvider.class);
		assertDisabled(listingProvider, timePlugin.actionRenameSnapshot);

		createSnaplessTrace();
		addSnapshots();
		assertDisabled(listingProvider, timePlugin.actionRenameSnapshot);

		traceManager.openTrace(tb.trace);
		waitForSwing();
		assertDisabled(listingProvider, timePlugin.actionRenameSnapshot);

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertEnabled(listingProvider, timePlugin.actionRenameSnapshot);

		traceManager.activateSnap(10);
		waitForSwing();
		performEnabledAction(listingProvider, timePlugin.actionRenameSnapshot, false);
		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		assertEquals("Snap 10", dialog.getValue());

		dialog.setValue("My Snapshot");
		dialog.close(); // isCancelled (private) defaults to false
		waitForSwing();

		DBTraceSnapshot snapshot = tb.trace.getTimeManager().getSnapshot(10, false);
		assertEquals("My Snapshot", snapshot.getDescription());

		// TODO: Test cancelled has no effect
	}

	@Test
	public void testEmpty() {
		assertProviderEmpty();
	}

	@Test
	public void testActivateThenAddSnapshotsPopulatesProvider() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderEmpty();

		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderPopulated();
	}

	@Test
	public void testActivateByThreadThenAddSnapshotsPopulatesProvider() throws Exception {
		createSnaplessTrace();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.trace.getThreadManager().createThread("Thread 1", 0);
		}
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderEmpty();

		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderPopulated();
	}

	@Test
	public void testAddSnapshotsThenActivatePopulatesProvider() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated();
	}

	@Test
	public void testDeleteSnapshotUpdatesProvider() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getTimeManager().getSnapshot(10, false).delete();
		}
		waitForDomainObject(tb.trace);

		assertEquals(1, timeProvider.mainPanel.snapshotTableModel.getModelData().size());
	}

	@Test
	public void testUndoRedo() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderEmpty();

		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderPopulated();

		undo(tb.trace);

		assertProviderEmpty();

		redo(tb.trace);

		assertProviderPopulated();
	}

	@Test
	public void testAbort() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderEmpty();

		try (Transaction tx = tb.startTransaction()) {
			addSnapshots();
			waitForDomainObject(tb.trace);

			assertProviderPopulated();

			tx.abort();
		}
		waitForDomainObject(tb.trace);

		assertProviderEmpty();
	}

	@Test
	public void testCloseEmptiesProvider() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated();

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	public void testEditDescription() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		SnapshotRow row = timeProvider.mainPanel.snapshotTableModel.getModelData().get(0);
		runSwing(() -> row.setDescription("Custom Description"));
		waitForDomainObject(tb.trace);

		assertEquals("Custom Description",
			tb.trace.getTimeManager().getSnapshot(0, false).getDescription());
	}

	@Test
	public void testActivateSnapSelectsRow() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		List<SnapshotRow> data = timeProvider.mainPanel.snapshotTableModel.getModelData();

		traceManager.activateSnap(0);
		waitForSwing();

		assertEquals(data.get(0), timeProvider.mainPanel.snapshotFilterPanel.getSelectedItem());

		traceManager.activateSnap(10);
		waitForSwing();

		assertEquals(data.get(1), timeProvider.mainPanel.snapshotFilterPanel.getSelectedItem());

		traceManager.activateSnap(5);
		waitForSwing();

		assertNull(timeProvider.mainPanel.snapshotFilterPanel.getSelectedItem());
	}

	@Test
	public void testDoubleClickRowActivatesSnap() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		clickTableCell(timeProvider.mainPanel.snapshotTable, 0, 0, 2);
		assertEquals(0, traceManager.getCurrentSnap());

		clickTableCell(timeProvider.mainPanel.snapshotTable, 1, 0, 2);
		assertEquals(10, traceManager.getCurrentSnap());
	}

	@Test
	public void testAddScratchThenActivateIsHidden() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		addScratchSnapshot();
		waitForDomainObject(tb.trace);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		List<SnapshotRow> data = timeProvider.mainPanel.snapshotTableModel.getModelData();
		assertEquals(2, data.size());
		for (SnapshotRow row : data) {
			assertTrue(row.getSnap() >= 0);
		}
	}

	@Test
	public void testActiveThenAddScratchIsHidden() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		waitForDomainObject(tb.trace);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(2, timeProvider.mainPanel.snapshotTableModel.getModelData().size());

		addScratchSnapshot();
		waitForDomainObject(tb.trace);

		List<SnapshotRow> data = timeProvider.mainPanel.snapshotTableModel.getModelData();
		assertEquals(2, data.size());
		for (SnapshotRow row : data) {
			assertTrue(row.getSnap() >= 0);
		}
	}

	@Test
	public void testAddScratchThenActivateThenToggleIsShown() throws Exception {
		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		addScratchSnapshot();
		waitForDomainObject(tb.trace);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(true, timeProvider.hideScratch);
		assertEquals(2, timeProvider.mainPanel.snapshotTableModel.getModelData().size());

		performAction(timeProvider.actionHideScratch);

		assertEquals(false, timeProvider.hideScratch);
		assertEquals(3, timeProvider.mainPanel.snapshotTableModel.getModelData().size());

		performAction(timeProvider.actionHideScratch);

		assertEquals(true, timeProvider.hideScratch);
		assertEquals(2, timeProvider.mainPanel.snapshotTableModel.getModelData().size());
	}

	@Test
	public void testToggleThenAddScratchThenActivateIsShown() throws Exception {
		performAction(timeProvider.actionHideScratch);

		createSnaplessTrace();
		traceManager.openTrace(tb.trace);
		addSnapshots();
		addScratchSnapshot();
		waitForDomainObject(tb.trace);

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(false, timeProvider.hideScratch);
		assertEquals(3, timeProvider.mainPanel.snapshotTableModel.getModelData().size());
	}
}
