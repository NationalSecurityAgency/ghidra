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

import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerLegacyThreadsPanel.ThreadTableColumns;
import ghidra.app.services.TraceRecorder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.database.UndoableTransaction;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerThreadsProviderLegacyTest extends AbstractGhidraHeadedDebuggerGUITest {

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
			thread1 = manager.addThread("Processes[1].Threads[1]", Lifespan.nowOn(0));
			thread1.setComment("A comment");
			thread2 = manager.addThread("Processes[1].Threads[2]", Lifespan.span(5, 10));
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
		List<ThreadRow> threadsDisplayed =
			threadsProvider.legacyPanel.threadTableModel.getModelData();
		assertTrue(threadsDisplayed.isEmpty());
	}

	protected void assertThreadsPopulated() {
		List<ThreadRow> threadsDisplayed =
			threadsProvider.legacyPanel.threadTableModel.getModelData();
		assertEquals(2, threadsDisplayed.size());

		ThreadRow thread1Record = threadsDisplayed.get(0);
		assertEquals(thread1, thread1Record.getThread());
		assertEquals("Processes[1].Threads[1]", thread1Record.getName());
		assertEquals(Lifespan.nowOn(0), thread1Record.getLifespan());
		assertEquals(0, thread1Record.getCreationSnap());
		assertEquals("", thread1Record.getDestructionSnap());
		assertEquals(tb.trace, thread1Record.getTrace());
		assertEquals(ThreadState.ALIVE, thread1Record.getState());
		assertEquals("A comment", thread1Record.getComment());

		ThreadRow thread2Record = threadsDisplayed.get(1);
		assertEquals(thread2, thread2Record.getThread());
	}

	protected void assertNoThreadSelected() {
		assertNull(threadsProvider.legacyPanel.threadFilterPanel.getSelectedItem());
	}

	protected void assertThreadSelected(TraceThread thread) {
		ThreadRow row = threadsProvider.legacyPanel.threadFilterPanel.getSelectedItem();
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

		assertEquals(1, threadsProvider.legacyPanel.spanRenderer.getFullRange().max().longValue());

		try (UndoableTransaction tid = tb.startTransaction()) {
			manager.getSnapshot(10, true);
		}
		waitForSwing();

		assertEquals(11, threadsProvider.legacyPanel.spanRenderer.getFullRange().max().longValue());
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

		assertEquals("15", threadsProvider.legacyPanel.threadTableModel.getModelData()
				.get(0)
				.getDestructionSnap());
		// NOTE: Plot max is based on time table, never thread destruction
	}

	@Test
	public void testDeleteThreadUpdatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(2, threadsProvider.legacyPanel.threadTableModel.getModelData().size());

		try (UndoableTransaction tid = tb.startTransaction()) {
			thread2.delete();
		}
		waitForSwing();

		assertEquals(1, threadsProvider.legacyPanel.threadTableModel.getModelData().size());
		// NOTE: Plot max is based on time table, never thread destruction
	}

	@Test
	public void testEditThreadFields() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		runSwing(() -> {
			threadsProvider.legacyPanel.threadTableModel.setValueAt("My Thread", 0,
				ThreadTableColumns.NAME.ordinal());
			threadsProvider.legacyPanel.threadTableModel.setValueAt("A different comment", 0,
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

		clickTableCellWithButton(threadsProvider.legacyPanel.threadTable, 1, 0, MouseEvent.BUTTON1);

		waitForPass(() -> {
			assertThreadSelected(thread2);
			assertEquals(thread2, traceManager.getCurrentThread());
		});
	}

	@Test
	public void testActivateSnapUpdatesTimelineCursor() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertThreadsPopulated();
		assertEquals(0, traceManager.getCurrentSnap());
		assertEquals(0, threadsProvider.legacyPanel.headerRenderer.getCursorPosition().longValue());

		traceManager.activateSnap(6);
		waitForSwing();

		assertEquals(6, threadsProvider.legacyPanel.headerRenderer.getCursorPosition().longValue());
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

		tb.close();

		createTestModel();
		mb.createTestProcessesAndThreads();
		// Threads needs registers to be recognized by the recorder
		mb.createTestThreadRegisterBanks();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1));
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
