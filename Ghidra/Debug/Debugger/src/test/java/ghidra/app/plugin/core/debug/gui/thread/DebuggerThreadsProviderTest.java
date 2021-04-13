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
package ghidra.app.plugin.core.debug.gui.thread;

import static org.junit.Assert.*;

import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.TraceRecorder;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.database.UndoableTransaction;

public class DebuggerThreadsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected DebuggerThreadsPlugin threadsPlugin;
	protected DebuggerThreadsProvider threadsProvider;

	protected TraceThread thread1;
	protected TraceThread thread2;

	@Before
	public void setUpThreadsProviderTest() throws Exception {
		threadsPlugin = addPlugin(tool, DebuggerThreadsPlugin.class);
		threadsProvider = waitForComponentProvider(DebuggerThreadsProvider.class);
	}

	protected void addThreads() throws Exception {
		TraceThreadManager manager = tb.trace.getThreadManager();
		try (UndoableTransaction tid = tb.startTransaction()) {
			thread1 = manager.addThread("Thread 1", Range.atLeast(0L));
			thread1.setComment("A comment");
			thread2 = manager.addThread("Thread 2", Range.closed(5L, 10L));
			thread2.setComment("Another comment");
		}
	}

	/**
	 * Check that there exist no tabs, and that the tab row is invisible
	 */
	protected void assertZeroTabs() {
		assertEquals(0, threadsProvider.traceTabs.getList().getModel().getSize());
		assertEquals("Tab row should not be visible", 0,
			threadsProvider.traceTabs.getVisibleRect().height);
	}

	/**
	 * Check that exactly one tab exists, and that the tab row is visible
	 */
	protected void assertOneTabPopulated() {
		assertEquals(1, threadsProvider.traceTabs.getList().getModel().getSize());
		assertNotEquals("Tab row should be visible", 0,
			threadsProvider.traceTabs.getVisibleRect().height);
	}

	protected void assertNoTabSelected() {
		assertTabSelected(null);
	}

	protected void assertTabSelected(Trace trace) {
		assertEquals(trace, threadsProvider.traceTabs.getSelectedItem());
	}

	protected void assertThreadsEmpty() {
		List<ThreadRow> threadsDisplayed = threadsProvider.threadTableModel.getModelData();
		assertTrue(threadsDisplayed.isEmpty());
	}

	protected void assertThreadsPopulated() {
		List<ThreadRow> threadsDisplayed = threadsProvider.threadTableModel.getModelData();
		assertEquals(2, threadsDisplayed.size());

		ThreadRow thread1Record = threadsDisplayed.get(0);
		assertEquals(thread1, thread1Record.getThread());
		assertEquals("Thread 1", thread1Record.getName());
		assertEquals(Range.atLeast(0L), thread1Record.getLifespan());
		assertEquals(0, thread1Record.getCreationSnap());
		assertEquals("", thread1Record.getDestructionSnap());
		assertEquals(tb.trace, thread1Record.getTrace());
		assertEquals(ThreadState.ALIVE, thread1Record.getState());
		assertEquals("A comment", thread1Record.getComment());

		ThreadRow thread2Record = threadsDisplayed.get(1);
		assertEquals(thread2, thread2Record.getThread());
	}

	protected void assertNoThreadSelected() {
		assertNull(threadsProvider.threadFilterPanel.getSelectedItem());
	}

	protected void assertThreadSelected(TraceThread thread) {
		ThreadRow row = threadsProvider.threadFilterPanel.getSelectedItem();
		assertNotNull(row);
		assertEquals(thread, row.getThread());
	}

	protected void assertProviderEmpty() {
		assertZeroTabs();
		assertThreadsEmpty();
	}

	@Test
	public void testEmpty() {
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testOpenTracePopupatesTab() throws Exception {
		createAndOpenTrace();
		waitForSwing();

		assertOneTabPopulated();
		assertNoTabSelected();
		assertThreadsEmpty();
	}

	@Test
	public void testActivateTraceSelectsTab() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertOneTabPopulated();
		assertTabSelected(tb.trace);

		traceManager.activateTrace(null);
		waitForSwing();

		assertOneTabPopulated();
		assertNoTabSelected();
	}

	@Test
	public void testSelectTabActivatesTrace() throws Exception {
		createAndOpenTrace();
		waitForSwing();
		threadsProvider.traceTabs.setSelectedItem(tb.trace);
		waitForSwing();

		assertEquals(tb.trace, traceManager.getCurrentTrace());
		assertEquals(tb.trace, threadsProvider.current.getTrace());
	}

	@Test
	public void testActivateNoTraceEmptiesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated(); // Sanity

		traceManager.activateTrace(null);
		waitForSwing();

		assertThreadsEmpty();
	}

	@Test
	public void testCurrentTraceClosedUpdatesTabs() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertOneTabPopulated();
		assertTabSelected(tb.trace);

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertZeroTabs();
		assertNoTabSelected();
	}

	@Test
	public void testCurrentTraceClosedEmptiesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertThreadsEmpty();
	}

	@Test
	public void testCloseTraceTabPopupMenuItem() throws Exception {
		createAndOpenTrace();
		waitForSwing();

		assertOneTabPopulated(); // pre-check
		clickListItem(threadsProvider.traceTabs.getList(), 0, MouseEvent.BUTTON3);
		waitForSwing();
		Set<String> expected = Set.of("Close " + tb.trace.getName());
		assertMenu(expected, expected);

		clickSubMenuItemByText("Close " + tb.trace.getName());
		waitForSwing();

		waitForPass(() -> {
			assertEquals(Set.of(), traceManager.getOpenTraces());
		});
	}

	@Test
	public void testActivateThenAddThreadsPopulatesProvider() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		addThreads();
		waitForSwing();

		assertThreadsPopulated();
	}

	@Test
	public void testAddThreadsThenActivatePopulatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		waitForSwing();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();
	}

	@Test
	public void testAddSnapUpdatesTimelineMax() throws Exception {
		createAndOpenTrace();
		TraceTimeManager manager = tb.trace.getTimeManager();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(0, threadsProvider.threadTimeline.getMaxSnapAtLeast());

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.getSnapshot(10, true);
		}
		waitForSwing();

		assertEquals(10, threadsProvider.threadTimeline.getMaxSnapAtLeast());
	}

	// NOTE: Do not test delete updates timeline max, as maxSnap does not reflect deletion

	@Test
	public void testChangeThreadUpdatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		try (UndoableTransaction tid = tb.startTransaction()) {
			thread1.setDestructionSnap(15);
		}
		waitForSwing();

		assertEquals("15",
			threadsProvider.threadTableModel.getModelData().get(0).getDestructionSnap());
		assertEquals(Range.closed(-1d, 16d),
			threadsProvider.threadTimeline.timeline.getViewRange());
	}

	@Test
	public void testDeleteThreadUpdatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(Range.closed(-1d, 11d),
			threadsProvider.threadTimeline.timeline.getViewRange());

		try (UndoableTransaction tid = tb.startTransaction()) {
			thread2.delete();
		}
		waitForSwing();

		assertEquals(1, threadsProvider.threadTableModel.getModelData().size());
		assertEquals(Range.closed(-1d, 1d), threadsProvider.threadTimeline.timeline.getViewRange());
	}

	@Test
	public void testEditThreadFields() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		runSwing(() -> {
			threadsProvider.threadTableModel.setValueAt("My Thread", 0,
				ThreadTableColumns.NAME.ordinal());
			threadsProvider.threadTableModel.setValueAt("A different comment", 0,
				ThreadTableColumns.COMMENT.ordinal());
		});

		assertEquals("My Thread", thread1.getName());
		assertEquals("A different comment", thread1.getComment());
	}

	@Test
	public void testUndoRedoCausesUpdateInProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();

		undo(tb.trace);
		assertThreadsEmpty();

		redo(tb.trace);
		assertThreadsPopulated();
	}

	@Test
	public void testActivateThreadSelectsThread() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();
		assertThreadSelected(thread1);

		traceManager.activateThread(thread2);
		waitForSwing();

		assertThreadSelected(thread2);
	}

	@Test
	public void testSelectThreadInTableActivatesThread() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForDomainObject(tb.trace);

		assertThreadsPopulated();
		assertThreadSelected(thread1); // Manager selects default if not live

		clickTableCellWithButton(threadsProvider.threadTable, 1, 0, MouseEvent.BUTTON1);

		waitForPass(() -> {
			assertThreadSelected(thread2);
			assertEquals(thread2, traceManager.getCurrentThread());
		});
	}

	@Test
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testSelectThreadInTimelineActivatesThread() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForDomainObject(tb.trace);

		assertThreadsPopulated();
		assertThreadSelected(thread1);

		// Otherwise, this test fails unpredictably
		waitForPass(noExc(() -> {
			Rectangle b = threadsProvider.threadTimeline.getCellBounds(thread2);
			threadsProvider.threadTimeline.scrollRectToVisible(b);
			Point tsl = threadsProvider.threadTimeline.getLocationOnScreen();
			Point vp = threadsProvider.threadTimeline.getViewport().getViewPosition();
			Point m =
				new Point(tsl.x + b.x + b.width / 2 - vp.x, tsl.y + b.y + b.height / 2 - vp.y);
			clickMouse(MouseEvent.BUTTON1, m);
			waitForSwing();

			assertThreadSelected(thread2);
			assertEquals(thread2, traceManager.getCurrentThread());
		}));
	}

	@Test
	public void testActivateSnapUpdatesTimelineCursor() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();
		assertEquals(0, traceManager.getCurrentSnap());
		assertEquals(0, (int) threadsProvider.threadTimeline.topCursor.getValue());

		traceManager.activateSnap(6);
		waitForSwing();

		assertEquals(6, (int) threadsProvider.threadTimeline.topCursor.getValue());
	}

	@Test
	public void testSeekTimelineActivatesSnap() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();
		assertEquals(0, traceManager.getCurrentSnap());
		assertEquals(0, (int) threadsProvider.threadTimeline.topCursor.getValue());

		threadsProvider.threadTimeline.topCursor.requestValue(6, EventTrigger.GUI_ACTION);
		waitForSwing();

		assertEquals(6, traceManager.getCurrentSnap());
	}

	@Test
	public void testActionStepTraceBackward() throws Exception {
		assertFalse(threadsProvider.actionStepSnapBackward.isEnabled());

		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertFalse(threadsProvider.actionStepSnapBackward.isEnabled());

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getTimeManager().getSnapshot(10, true);
		}
		waitForDomainObject(tb.trace);

		assertFalse(threadsProvider.actionStepSnapBackward.isEnabled());

		traceManager.activateSnap(2);
		waitForSwing();

		assertTrue(threadsProvider.actionStepSnapBackward.isEnabled());

		performAction(threadsProvider.actionStepSnapBackward);
		waitForSwing();

		assertEquals(1, traceManager.getCurrentSnap());
	}

	@Test
	public void testActionStepTraceForward() throws Exception {
		assertFalse(threadsProvider.actionStepSnapForward.isEnabled());

		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertFalse(threadsProvider.actionStepSnapForward.isEnabled());

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getTimeManager().getSnapshot(10, true);
		}
		waitForDomainObject(tb.trace);

		assertTrue(threadsProvider.actionStepSnapForward.isEnabled());

		performAction(threadsProvider.actionStepSnapForward);
		waitForSwing();

		assertEquals(1, traceManager.getCurrentSnap());
		assertTrue(threadsProvider.actionStepSnapForward.isEnabled());

		traceManager.activateSnap(10);
		waitForSwing();

		assertFalse(threadsProvider.actionStepSnapForward.isEnabled());
	}

	@Test
	public void testActionSeekTracePresent() throws Exception {
		assertTrue(threadsProvider.actionSeekTracePresent.isSelected());

		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentSnap());

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getTimeManager().createSnapshot("Next snapshot");
		}
		waitForDomainObject(tb.trace);

		// Not live, so no seek
		assertEquals(0, traceManager.getCurrentSnap());

		createTestModel();
		mb.createTestProcessesAndThreads();
		// Threads needs registers to be recognized by the recorder
		mb.createTestThreadRegisterBanks();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		// Wait till two threads are observed in the database
		waitForPass(() -> assertEquals(2, trace.getThreadManager().getAllThreads().size()));
		waitForSwing();

		TraceSnapshot snapshot = recorder.forceSnapshot();
		waitForDomainObject(trace);

		assertEquals(snapshot.getKey(), traceManager.getCurrentSnap());

		performAction(threadsProvider.actionSeekTracePresent);
		waitForSwing();

		assertFalse(threadsProvider.actionSeekTracePresent.isSelected());

		recorder.forceSnapshot();
		waitForSwing();

		assertEquals(snapshot.getKey(), traceManager.getCurrentSnap());
	}
}
