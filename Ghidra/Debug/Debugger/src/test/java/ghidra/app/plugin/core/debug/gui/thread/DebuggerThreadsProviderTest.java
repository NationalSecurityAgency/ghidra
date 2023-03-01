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
import java.io.IOException;
import java.util.Objects;
import java.util.Set;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.table.*;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.app.plugin.core.debug.gui.model.QueryPanelTestHelper;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.mapping.ObjectBasedDebuggerTargetTraceMapper;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.table.GhidraTable;

@Category(NightlyCategory.class)
public class DebuggerThreadsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerThreadsProvider provider;

	protected TraceObjectThread thread1;
	protected TraceObjectThread thread2;

	protected SchemaContext ctx;

	@Override
	protected DebuggerTargetTraceMapper createTargetTraceMapper(TargetObject target)
			throws Exception {
		return new ObjectBasedDebuggerTargetTraceMapper(target,
			new LanguageID("DATA:BE:64:default"), new CompilerSpecID("pointer64"), Set.of());
	}

	@Override
	protected TraceRecorder recordAndWaitSync() throws Throwable {
		TraceRecorder recorder = super.recordAndWaitSync();
		useTrace(recorder.getTrace());
		return recorder;
	}

	@Override
	protected TargetObject chooseTarget() {
		return mb.testModel.session;
	}

	@Override
	protected void createTrace(String langID) throws IOException {
		super.createTrace(langID);
		try {
			activateObjectsMode();
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void useTrace(Trace trace) {
		super.useTrace(trace);
		if (trace.getObjectManager().getRootObject() != null) {
			// If live, recorder will have created it
			return;
		}
		try {
			activateObjectsMode();
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	public void activateObjectsMode() throws Exception {
		// NOTE the use of index='1' allowing object-based managers to ID unique path
		ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Processes' schema='ProcessContainer' />
				    </schema>
				    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element index='1' schema='Process' />
				    </schema>
				    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Threads' schema='ThreadContainer' />
				    </schema>
				    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Thread' />
				    </schema>
				    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Thread' />
				    </schema>
				</context>""");

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	protected TraceObjectThread addThread(int index, Lifespan lifespan, String comment) {
		TraceObjectManager om = tb.trace.getObjectManager();
		PathPattern threadPattern = new PathPattern(PathUtils.parse("Processes[1].Threads[]"));
		TraceObjectThread thread = Objects.requireNonNull(om.createObject(
			TraceObjectKeyPath.of(threadPattern.applyIntKeys(index).getSingletonPath()))
				.insert(lifespan, ConflictResolution.TRUNCATE)
				.getDestination(null)
				.queryInterface(TraceObjectThread.class));
		thread.getObject()
				.setAttribute(lifespan, TargetExecutionStateful.STATE_ATTRIBUTE_NAME,
					TargetExecutionState.STOPPED.name());
		thread.getObject().setAttribute(lifespan, TraceObjectThread.KEY_COMMENT, comment);
		return thread;
	}

	protected void addThreads() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			thread1 = addThread(1, Lifespan.nowOn(0), "A comment");
			thread2 = addThread(2, Lifespan.span(0, 10), "Another comment");
		}
	}

	/**
	 * Check that there exist no tabs, and that the tab row is invisible
	 */
	protected void assertZeroTabs() {
		assertEquals(0, provider.traceTabs.getList().getModel().getSize());
		assertEquals("Tab row should not be visible", 0,
			provider.traceTabs.getVisibleRect().height);
	}

	/**
	 * Check that exactly one tab exists, and that the tab row is visible
	 */
	protected void assertOneTabPopulated() {
		assertEquals(1, provider.traceTabs.getList().getModel().getSize());
		assertNotEquals("Tab row should be visible", 0,
			provider.traceTabs.getVisibleRect().height);
	}

	protected void assertNoTabSelected() {
		assertTabSelected(null);
	}

	protected void assertTabSelected(Trace trace) {
		assertEquals(trace, provider.traceTabs.getSelectedItem());
	}

	protected void assertThreadsTableSize(int size) {
		assertEquals(size, provider.panel.getAllItems().size());
	}

	protected void assertThreadsEmpty() {
		assertThreadsTableSize(0);
	}

	protected void assertThreadRow(int position, Object object, String name, Long created,
			Long destroyed, TargetExecutionState state, String comment) {
		// NB. Not testing plot, since that's unmodified from generic ObjectTable
		ValueRow row = provider.panel.getAllItems().get(position);
		DynamicTableColumn<ValueRow, ?, Trace> nameCol =
			provider.panel.getColumnByNameAndType("Name", ValueRow.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> createdCol =
			provider.panel.getColumnByNameAndType("Created", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> destroyedCol =
			provider.panel.getColumnByNameAndType("Destroyed", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> stateCol =
			provider.panel.getColumnByNameAndType("State", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> commentCol =
			provider.panel.getColumnByNameAndType("Comment", ValueProperty.class).getValue();

		assertSame(object, row.getValue().getValue());
		assertEquals(name, rowColDisplay(row, nameCol));
		assertEquals(created, rowColVal(row, createdCol));
		assertEquals(destroyed, rowColVal(row, destroyedCol));
		assertEquals(state.name(), rowColVal(row, stateCol));
		assertEquals(comment, rowColVal(row, commentCol));
	}

	protected void assertThreadsPopulated() {
		assertThreadsTableSize(2);

		assertThreadRow(0, thread1.getObject(), "Processes[1].Threads[1]", 0L, null,
			TargetExecutionState.STOPPED, "A comment");
		assertThreadRow(1, thread2.getObject(), "Processes[1].Threads[2]", 0L, 10L,
			TargetExecutionState.STOPPED, "Another comment");
	}

	protected void assertNoThreadSelected() {
		assertNull(provider.panel.getSelectedItem());
	}

	protected void assertThreadSelected(TraceObjectThread thread) {
		ValueRow row = provider.panel.getSelectedItem();
		assertNotNull(row);
		assertEquals(thread.getObject(), row.getValue().getChild());
	}

	protected void assertProviderEmpty() {
		assertZeroTabs();
		assertThreadsEmpty();
	}

	@Before
	public void setUpThreadsProviderTest() throws Exception {
		addPlugin(tool, DebuggerThreadsPlugin.class);
		provider = waitForComponentProvider(DebuggerThreadsProvider.class);
	}

	@After
	public void tearDownThreadsProviderTest() throws Exception {
		traceManager.activate(DebuggerCoordinates.NOWHERE);
		waitForTasks();
		runSwing(() -> traceManager.closeAllTraces());
	}

	@Test
	public void testEmpty() {
		waitForTasks();
		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testOpenTracePopupatesTab() throws Exception {
		createAndOpenTrace();
		waitForTasks();

		waitForPass(() -> {
			assertOneTabPopulated();
			assertNoTabSelected();
			assertThreadsEmpty();
		});
	}

	@Test
	public void testActivateTraceSelectsTab() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertOneTabPopulated();
			assertTabSelected(tb.trace);
		});

		traceManager.activateTrace(null);
		waitForTasks();

		waitForPass(() -> {
			assertOneTabPopulated();
			assertNoTabSelected();
		});
	}

	@Test
	public void testSelectTabActivatesTrace() throws Exception {
		createAndOpenTrace();
		waitForTasks();
		provider.traceTabs.setSelectedItem(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertEquals(tb.trace, traceManager.getCurrentTrace());
			assertEquals(tb.trace, provider.current.getTrace());
		});
	}

	@Test
	public void testActivateNoTraceEmptiesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertThreadsPopulated());

		traceManager.activateTrace(null);
		waitForTasks();

		waitForPass(() -> assertThreadsEmpty());
	}

	@Test
	public void testCurrentTraceClosedUpdatesTabs() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertOneTabPopulated();
			assertTabSelected(tb.trace);
		});

		traceManager.closeTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertZeroTabs();
			assertNoTabSelected();
		});
	}

	@Test
	public void testCurrentTraceClosedEmptiesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertThreadsPopulated());

		traceManager.closeTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertThreadsEmpty());
	}

	@Test
	public void testCloseTraceTabPopupMenuItem() throws Exception {
		createAndOpenTrace();
		waitForTasks();

		waitForPass(() -> assertOneTabPopulated());
		clickListItem(provider.traceTabs.getList(), 0, MouseEvent.BUTTON3);
		waitForTasks();
		Set<String> expected = Set.of("Close " + tb.trace.getName());
		assertMenu(expected, expected);

		clickSubMenuItemByText("Close " + tb.trace.getName());
		waitForTasks();

		waitForPass(() -> {
			assertEquals(Set.of(), traceManager.getOpenTraces());
		});
	}

	@Test
	public void testActivateThenAddThreadsPopulatesProvider() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		addThreads();
		waitForTasks();

		waitForPass(() -> assertThreadsPopulated());
	}

	@Test
	public void testAddThreadsThenActivatePopulatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		waitForTasks();

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertThreadsPopulated());
	}

	@Test
	public void testAddSnapUpdatesTimelineMax() throws Exception {
		createAndOpenTrace();
		TraceTimeManager manager = tb.trace.getTimeManager();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			SpannedRenderer<Long> renderer =
				QueryPanelTestHelper.getSpannedCellRenderer(provider.panel);
			assertEquals(1, renderer.getFullRange().max().longValue());
		});

		try (Transaction tx = tb.startTransaction()) {
			manager.getSnapshot(10, true);
		}
		waitForSwing();

		waitForPass(() -> {
			SpannedRenderer<Long> renderer =
				QueryPanelTestHelper.getSpannedCellRenderer(provider.panel);
			assertEquals(11, renderer.getFullRange().max().longValue());
		});
	}

	// NOTE: Do not test delete updates timeline max, as maxSnap does not reflect deletion

	@Test
	public void testChangeThreadUpdatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		try (Transaction tx = tb.startTransaction()) {
			thread1.getObject().removeTree(Lifespan.nowOn(16));
		}
		waitForTasks();

		waitForPass(() -> {
			assertThreadRow(0, thread1.getObject(), "Processes[1].Threads[1]", 0L, 15L,
				TargetExecutionState.STOPPED, "A comment");
		});
		// NOTE: Destruction will not be visible in plot unless snapshot 15 is created
	}

	@Test
	public void testDeleteThreadUpdatesProvider() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertThreadsTableSize(2));

		try (Transaction tx = tb.startTransaction()) {
			thread2.getObject().removeTree(Lifespan.ALL);
		}
		waitForTasks();

		waitForPass(() -> assertThreadsTableSize(1));
	}

	@Test
	public void testEditThreadComment() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		int commentViewIdx =
			provider.panel.getColumnByNameAndType("Comment", ValueProperty.class).getKey();
		ObjectTableModel tableModel = QueryPanelTestHelper.getTableModel(provider.panel);
		GhidraTable table = QueryPanelTestHelper.getTable(provider.panel);
		int commentModelIdx = table.convertColumnIndexToModel(commentViewIdx);

		runSwing(() -> {
			tableModel.setValueAt(new ValueFixedProperty<>("A different comment"), 0,
				commentModelIdx);
		});
		waitForTasks();

		waitForPass(() -> assertEquals("A different comment",
			thread1.getObject().getAttribute(0, TraceObjectThread.KEY_COMMENT).getValue()));
	}

	@Test
	public void testUndoRedoCausesUpdateInProvider() throws Exception {
		createAndOpenTrace();
		addThreads();

		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> assertThreadsPopulated());

		undo(tb.trace);
		waitForTasks();
		waitForPass(() -> assertThreadsEmpty());

		redo(tb.trace);
		waitForTasks();
		waitForPass(() -> assertThreadsPopulated());
	}

	@Test
	public void testActivateThreadSelectsThread() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertThreadsPopulated();
			assertThreadSelected(thread1);
		});

		traceManager.activateThread(thread2);
		waitForTasks();

		waitForPass(() -> assertThreadSelected(thread2));
	}

	@Test
	public void testDoubleClickThreadInTableActivatesThread() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertThreadsPopulated());

		GhidraTable table = QueryPanelTestHelper.getTable(provider.panel);
		clickTableCell(table, 1, 0, 2);
		assertEquals(thread2, traceManager.getCurrentThread());
	}

	@Test
	public void testActivateSnapUpdatesTimelineCursor() throws Exception {
		createAndOpenTrace();
		addThreads();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		RangeCursorTableHeaderRenderer<Long> renderer =
			QueryPanelTestHelper.getCursorHeaderRenderer(provider.panel);

		waitForPass(() -> {
			assertThreadsPopulated();
			assertEquals(0, traceManager.getCurrentSnap());
			assertEquals(Long.valueOf(0), renderer.getCursorPosition());
		});

		traceManager.activateSnap(6);
		waitForTasks();

		waitForPass(() -> assertEquals(Long.valueOf(6), renderer.getCursorPosition()));
	}
}
