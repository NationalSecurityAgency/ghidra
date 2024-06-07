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

import java.io.IOException;
import java.util.Objects;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.table.*;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.app.plugin.core.debug.gui.model.QueryPanelTestHelper;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServiceTestAccess;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.table.GhidraTable;

@Category(NightlyCategory.class)
public class DebuggerThreadsProviderTest extends AbstractGhidraHeadedDebuggerTest {
	// NOTE the use of index='1' allowing object-based managers to ID unique path
	public static final String CTX_XML = """
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
			        <interface name='Activatable' />
			    </schema>
			</context>""";

	DebuggerThreadsProvider provider;

	protected TraceObjectThread thread1;
	protected TraceObjectThread thread2;

	protected SchemaContext ctx;

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

	public void activateObjectsMode() throws Exception {
		ctx = XmlSchemaContext.deserialize(CTX_XML);

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

	protected void assertThreadsTableSize(int size) {
		assertEquals(size, provider.panel.getAllItems().size());
	}

	protected void assertThreadsEmpty() {
		assertThreadsTableSize(0);
	}

	protected void assertThreadRow(int position, Object object, String name,
			TargetExecutionState state, String comment) {
		// NB. Not testing plot, since that's unmodified from generic ObjectTable
		ValueRow row = provider.panel.getAllItems().get(position);
		var tableModel = QueryPanelTestHelper.getTableModel(provider.panel);
		GhidraTable table = QueryPanelTestHelper.getTable(provider.panel);
		DynamicTableColumn<ValueRow, ?, Trace> nameCol = QueryPanelTestHelper
				.getColumnByNameAndType(tableModel, table, "Name", ValueRow.class)
				.column();
		DynamicTableColumn<ValueRow, ?, Trace> stateCol = QueryPanelTestHelper
				.getColumnByNameAndType(tableModel, table, "State", ValueProperty.class)
				.column();
		DynamicTableColumn<ValueRow, ?, Trace> commentCol = QueryPanelTestHelper
				.getColumnByNameAndType(tableModel, table, "Comment", ValueProperty.class)
				.column();

		assertSame(object, row.getValue().getValue());
		assertEquals(name, rowColDisplay(row, nameCol));
		assertEquals(state.name(), rowColVal(row, stateCol));
		assertEquals(comment, rowColVal(row, commentCol));
	}

	protected void assertThreadsPopulated() {
		assertThreadsTableSize(2);

		assertThreadRow(0, thread1.getObject(), "Processes[1].Threads[1]",
			TargetExecutionState.STOPPED, "A comment");
		assertThreadRow(1, thread2.getObject(), "Processes[1].Threads[2]",
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
	public void testActivateNoTraceEmptiesProvider() throws Exception {
		DebuggerTraceManagerServiceTestAccess.setEnsureActiveTrace(traceManager, false);
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
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertThreadRow(0, thread1.getObject(), "Processes[1].Threads[1]",
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

		var tableModel = QueryPanelTestHelper.getTableModel(provider.panel);
		GhidraTable table = QueryPanelTestHelper.getTable(provider.panel);
		int commentModelIdx = QueryPanelTestHelper
				.getColumnByNameAndType(tableModel, table, "Comment", ValueProperty.class)
				.modelIndex();
		assertNotEquals(-1, commentModelIdx);

		runSwing(() -> {
			tableModel.setValueAt(new ValueFixedProperty<>("A different comment"), 0,
				commentModelIdx);
		});
		waitForTasks();

		waitForPass(() -> assertEquals("A different comment",
			thread1.getObject().getAttribute(0, TraceObjectThread.KEY_COMMENT).getValue()));
	}

	// @Test // Not gonna with write-behind cache
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
