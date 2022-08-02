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
package ghidra.app.plugin.core.debug.gui.model;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Set;

import org.jdom.JDOMException;
import org.junit.*;

import com.google.common.collect.Range;

import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.GDynamicColumnTableModel;
import generic.Unique;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.PrimitiveRow;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.ObjectTreeModel.AbstractNode;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueValColumn;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.util.database.UndoableTransaction;

public class DebuggerModelProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected static final SchemaContext CTX;

	static {
		try {
			CTX = XmlSchemaContext.deserialize("" + //
				"<context>" + //
				"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
				"        <attribute name='Processes' schema='ProcessContainer' />" + //
				"        <interface name='EventScope' />" + //
				"    </schema>" + //
				"    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER' " + //
				"            attributeResync='ONCE'>" + //
				"        <element schema='Process' />" + //
				"    </schema>" + //
				"    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>" + //
				"        <attribute name='Threads' schema='ThreadContainer' />" + //
				"        <attribute name='Handles' schema='HandleContainer' />" + //
				"    </schema>" + //
				"    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER' " + //
				"            attributeResync='ONCE'>" + //
				"        <element schema='Thread' />" + //
				"    </schema>" + //
				"    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>" + //
				"        <interface name='Thread' />" + //
				"        <attribute name='_display' schema='STRING' />" + //
				"        <attribute name='_self' schema='Thread' />" + //
				"    </schema>" + //
				"    <schema name='HandleContainer' canonical='yes' elementResync='NEVER' " + //
				"            attributeResync='ONCE'>" + //
				"        <element schema='INT' />" + //
				"    </schema>" + //
				"</context>");
		}
		catch (JDOMException e) {
			throw new AssertionError();
		}
	}

	protected static Integer findColumnOfClass(GDynamicColumnTableModel<?, ?> model,
			Class<? extends DynamicTableColumn<?, ?, ?>> cls) {
		for (int i = 0; i < model.getColumnCount(); i++) {
			DynamicTableColumn<?, ?, ?> column = model.getColumn(i);
			if (cls.isAssignableFrom(column.getClass())) {
				return i;
			}
		}
		return null;
	}

	protected DebuggerModelPlugin modelPlugin;
	protected DebuggerModelProvider modelProvider;

	@Before
	public void setUpModelProviderTest() throws Exception {
		modelPlugin = addPlugin(tool, DebuggerModelPlugin.class);
		modelProvider = waitForComponentProvider(DebuggerModelProvider.class);

		// So I can manipulate the coordinates
		//addPlugin(tool, DebuggerThreadsPlugin.class);
	}

	@After
	public void tearDownModelProviderTest() throws Exception {
		traceManager.activate(DebuggerCoordinates.NOWHERE);
		waitForSwing();
		waitForCondition(() -> !modelProvider.objectsTreePanel.tree.isBusy());
		waitForCondition(() -> !modelProvider.elementsTablePanel.tableModel.isBusy());
		waitForCondition(() -> !modelProvider.attributesTablePanel.tableModel.isBusy());
		runSwing(() -> traceManager.closeAllTraces());
	}

	protected void populateSnapshots() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getTimeManager().getSnapshot(20, true);
		}
	}

	protected TraceObjectValue createSessionObject() throws Throwable {
		DBTraceObjectManager objects = tb.trace.getObjectManager();
		try (UndoableTransaction tid = tb.startTransaction()) {
			return objects.createRootObject(CTX.getSchema(new SchemaName("Session")));
		}
	}

	protected DBTraceObject createThread(long i, DBTraceObject prevThread) {
		DBTraceObjectManager objects = tb.trace.getObjectManager();
		TraceObjectKeyPath threadContainerPath = TraceObjectKeyPath.parse("Processes[0].Threads");
		DBTraceObject thread = objects.createObject(threadContainerPath.index(i));
		thread.insert(Range.closed(i, 10L), ConflictResolution.DENY);
		thread.insert(Range.atLeast(10 + i), ConflictResolution.DENY);
		thread.setAttribute(Range.atLeast(i), "Attribute " + i, "Some value");
		thread.setAttribute(Range.atLeast(i), "_display", "Thread " + i);
		thread.setAttribute(Range.atLeast(i), "_self", thread);
		if (prevThread != null) {
			thread.setAttribute(Range.atLeast(i), "_prev", prevThread);
			prevThread.setAttribute(Range.atLeast(i), "_next", thread);
		}
		objects.getRootObject()
				.setAttribute(Range.atLeast(i), TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME,
					thread);
		return thread;
	}

	protected void populateThreads() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceObject prevThread = null;
			for (long i = 0; i < 10; i++) {
				DBTraceObject thread = createThread(i, prevThread);
				prevThread = thread;
			}
		}
	}

	protected void addThread10() throws Throwable {
		DBTraceObjectManager objects = tb.trace.getObjectManager();
		try (UndoableTransaction tid = tb.startTransaction()) {
			createThread(10, objects.getObjectByCanonicalPath(
				TraceObjectKeyPath.parse("Processes[0].Threads[9]")));
		}
	}

	protected void populateHandles() throws Throwable {
		DBTraceObjectManager objects = tb.trace.getObjectManager();
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceObject handleContainer =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Handles"));
			handleContainer.insert(Range.atLeast(0L), ConflictResolution.DENY);
			for (int i = 0; i < 10; i++) {
				handleContainer.setElement(Range.atLeast((long) -i), i,
					(i * 0xdeadbeef) % 0xbadc0de);
			}
		}
	}

	protected void populateLinks() throws Throwable {
		DBTraceObjectManager objects = tb.trace.getObjectManager();
		TraceObjectKeyPath threadContainerPath = TraceObjectKeyPath.parse("Processes[0].Threads");
		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceObject linkContainer =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Links"));
			linkContainer.insert(Range.atLeast(0L), ConflictResolution.DENY);
			for (int i = 0; i < 10; i++) {
				linkContainer.setElement(Range.atLeast(0L), i,
					objects.getObjectByCanonicalPath(threadContainerPath.index(9 - i)));
			}
		}
	}

	protected void populateBoxedPrimitive() throws Throwable {
		DBTraceObjectManager objects = tb.trace.getObjectManager();
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceObject boxed =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Boxed"));
			boxed.insert(Range.atLeast(0L), ConflictResolution.DENY);
			boxed.setAttribute(Range.atLeast(2L), TargetObject.DISPLAY_ATTRIBUTE_NAME, "2");
			boxed.setAttribute(Range.atLeast(4L), TargetObject.DISPLAY_ATTRIBUTE_NAME, "4");
		}
	}

	protected void createTraceAndPopulateObjects() throws Throwable {
		createTrace();
		populateSnapshots();
		createSessionObject();
		populateThreads();
		populateHandles();
		populateLinks();
		populateBoxedPrimitive();
	}

	protected void assertPathIs(TraceObjectKeyPath path, int elemCount, int attrCount) {
		assertEquals(path, modelProvider.getPath());
		assertEquals(path.toString(), modelProvider.pathField.getText());
		AbstractNode item = modelProvider.objectsTreePanel.getSelectedItem();
		assertNotNull(item);
		assertEquals(path, item.getValue().getChild().getCanonicalPath());
		// Table model is threaded
		waitForPass(() -> assertEquals(elemCount,
			modelProvider.elementsTablePanel.tableModel.getModelData().size()));
		waitForPass(() -> assertEquals(attrCount,
			modelProvider.attributesTablePanel.tableModel.getModelData().size()));
	}

	protected void assertPathIsThreadsContainer() {
		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads"), 10, 0);
	}

	@Test
	public void testSetPathWOutTrace() throws Throwable {
		modelProvider.setPath(TraceObjectKeyPath.parse(""));
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse(""));
		waitForSwing();
	}

	@Test
	public void testSelectRootWOutTrace() throws Throwable {
		modelProvider.objectsTreePanel.setSelectedKeyPaths(Set.of(TraceObjectKeyPath.parse("")));
		waitForSwing();
	}

	@Test
	public void testSelectRootWOutObjects() throws Throwable {
		createTrace();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		modelProvider.objectsTreePanel.setSelectedKeyPaths(Set.of(TraceObjectKeyPath.parse("")));
		waitForSwing();
	}

	@Test
	public void testSetPathApi() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForSwing();

		assertPathIsThreadsContainer();
	}

	@Test
	public void testSetPathViaField() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.pathField.setText("Processes[0].Threads");
		modelProvider.pathField.getInputVerifier().verify(modelProvider.pathField);
		waitForSwing();

		assertPathIsThreadsContainer();
	}

	@Test
	public void testSetPathViaTree() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.objectsTreePanel
				.setSelectedKeyPaths(List.of(TraceObjectKeyPath.parse("Processes[0].Threads")));
		waitForSwing();

		waitForPass(() -> assertPathIsThreadsContainer());
	}

	@Test
	public void testSelectElementDisplaysAttributes() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForSwing();

		ValueRow selElem = waitForValue(() -> {
			List<ValueRow> rows = modelProvider.elementsTablePanel.tableModel.getModelData();
			if (rows.size() != 10) {
				return null;
			}
			return rows.get(2);
		});
		modelProvider.elementsTablePanel.setSelectedItem(selElem);
		waitForSwing();

		waitForPass(() -> assertEquals(3,
			modelProvider.attributesTablePanel.tableModel.getModelData().size()));
	}

	@Test
	public void testSetPathNoExist() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].NoSuch"));
		waitForSwing();

		assertEquals("No such object at path Processes[0].NoSuch", tool.getStatusInfo());
	}

	@Test
	public void testPrimitiveElements() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Handles"));
		waitForSwing();

		int valColIndex =
			waitForValue(() -> findColumnOfClass(modelProvider.elementsTablePanel.tableModel,
				TraceValueValColumn.class));

		waitForPass(() -> {
			for (int i = 0; i < 10; i++) {
				Object obj = modelProvider.elementsTablePanel.tableModel.getValueAt(i, valColIndex);
				assertTrue(obj instanceof PrimitiveRow);
				PrimitiveRow row = (PrimitiveRow) obj;
				assertEquals(Integer.toString((0xdeadbeef * i) % 0xbadc0de), row.getDisplay());
			}
		});
	}

	@Test
	public void testCancelEditPath() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForSwing();

		modelProvider.pathField.setText("SomeNonsenseToBeCancelled");
		triggerEscapeKey(modelProvider.pathField);
		waitForSwing();

		assertPathIsThreadsContainer();
	}

	@Test
	public void testDoubleClickLinkInElementsTable() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Links"));
		waitForSwing();

		ValueRow row2 = waitForValue(() -> {
			return modelProvider.elementsTablePanel.tableModel.getModelData()
					.stream()
					.filter(r -> r.getValue().getEntryKey().equals("[2]"))
					.findAny()
					.orElse(null);
		});
		modelProvider.elementsTablePanel.setSelectedItem(row2);
		waitForSwing();
		int rowIndex = waitForValue(() -> {
			int index = modelProvider.elementsTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.elementsTablePanel.table, rowIndex, 0, 2);

		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads[7]"), 0, 3);
	}

	@Test
	public void testDoubleClickObjectInElementsTable() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForSwing();

		ValueRow row2 = waitForValue(() -> {
			return modelProvider.elementsTablePanel.tableModel.getModelData()
					.stream()
					.filter(r -> r.getValue().getEntryKey().equals("[2]"))
					.findAny()
					.orElse(null);
		});
		modelProvider.elementsTablePanel.setSelectedItem(row2);
		waitForSwing();
		int rowIndex = waitForValue(() -> {
			int index = modelProvider.elementsTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.elementsTablePanel.table, rowIndex, 0, 2);

		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads[2]"), 0, 3);
	}

	protected void selectAttribute(String key) {
		PathRow rowNext = waitForValue(() -> {
			return modelProvider.attributesTablePanel.tableModel.getModelData()
					.stream()
					.filter(r -> {
						TraceObjectValue last = r.getPath().getLastEntry();
						if (last == null) {
							return false;
						}
						return last.getEntryKey().equals(key);
					})
					.findAny()
					.orElse(null);
		});
		modelProvider.attributesTablePanel.setSelectedItem(rowNext);
	}

	@Test
	public void testDoubleClickLinkInAttributesTable() throws Throwable {
		modelProvider.setShowHidden(true);
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads[2]"));
		waitForSwing();
		selectAttribute("_next");
		waitForSwing();

		int rowIndex = waitForValue(() -> {
			int index = modelProvider.attributesTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.attributesTablePanel.table, rowIndex, 0, 2);

		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads[3]"), 0, 5);
	}

	@Test
	public void testDoubleClickObjectInAttributesTable() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0]"));
		waitForSwing();

		PathRow rowNext = waitForValue(() -> {
			return modelProvider.attributesTablePanel.tableModel.getModelData()
					.stream()
					.filter(r -> {
						TraceObjectValue last = r.getPath().getLastEntry();
						if (last == null) {
							return false;
						}
						return last.getEntryKey().equals("Threads");
					})
					.findAny()
					.orElse(null);
		});
		modelProvider.attributesTablePanel.setSelectedItem(rowNext);
		waitForSwing();
		int rowIndex = waitForValue(() -> {
			int index = modelProvider.attributesTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.attributesTablePanel.table, rowIndex, 0, 2);

		assertPathIsThreadsContainer();
	}

	@Test
	public void testActionLimitToSnap() throws Throwable {
		assertFalse(modelProvider.isLimitToCurrentSnap());
		assertFalse(modelProvider.actionLimitToCurrentSnap.isSelected());
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForSwing();

		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads"), 10, 0);

		performAction(modelProvider.actionLimitToCurrentSnap);
		assertTrue(modelProvider.isLimitToCurrentSnap());
		assertTrue(modelProvider.actionLimitToCurrentSnap.isSelected());
		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads"), 1, 0);

		traceManager.activateSnap(5);
		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads"), 6, 0);

		performAction(modelProvider.actionLimitToCurrentSnap);
		assertFalse(modelProvider.isLimitToCurrentSnap());
		assertFalse(modelProvider.actionLimitToCurrentSnap.isSelected());
		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads"), 10, 0);
	}

	@Test
	public void testActionShowPrimitivesInTree() throws Throwable {
		createTraceAndPopulateObjects();
		assertFalse(modelProvider.isShowPrimitivesInTree());

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads[2]"));
		waitForSwing();

		AbstractNode nodeThread2 =
			waitForValue(() -> modelProvider.objectsTreePanel.getSelectedItem());
		assertEquals(1, nodeThread2.getChildren().size());

		performAction(modelProvider.actionShowPrimitivesInTree, modelProvider, true);
		assertTrue(modelProvider.isShowPrimitivesInTree());
		nodeThread2 = waitForValue(() -> modelProvider.objectsTreePanel.getSelectedItem());
		assertEquals(3, nodeThread2.getChildren().size());
		assertEquals(nodeThread2, modelProvider.objectsTreePanel.getSelectedItem());

		performAction(modelProvider.actionShowPrimitivesInTree, modelProvider, true);
		assertFalse(modelProvider.isShowPrimitivesInTree());
		nodeThread2 = waitForValue(() -> modelProvider.objectsTreePanel.getSelectedItem());
		assertEquals(1, nodeThread2.getChildren().size());
		assertEquals(nodeThread2, modelProvider.objectsTreePanel.getSelectedItem());
	}

	@Test
	public void testActionFollowLink() throws Throwable {
		modelProvider.setShowHidden(true);
		assertDisabled(modelProvider, modelProvider.actionFollowLink);
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads[2]"));
		waitForSwing();
		selectAttribute("_next");
		waitForSwing();

		assertEnabled(modelProvider, modelProvider.actionFollowLink);
		performAction(modelProvider.actionFollowLink, modelProvider, true);

		assertPathIs(TraceObjectKeyPath.parse("Processes[0].Threads[3]"), 0, 5);
	}

	@Test
	public void testActionCloneWindow() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads[2]"));
		waitForSwing();

		performAction(modelProvider.actionCloneWindow);

		DebuggerModelProvider clone = Unique.assertOne(modelPlugin.getDisconnectedProviders());

		assertEquals(tb.trace, clone.current.getTrace());
		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[2]"), clone.path);
	}

	@Test
	public void testPanesTrackAddElement() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		assertPathIsThreadsContainer();

		addThread10();
		waitForSwing();

		assertPathIs(path, 11, 0);
	}

	@Test
	public void testPanesTrackAddAttribute() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		assertPathIs(path, 0, 3);

		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceObject thread = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
			thread.setAttribute(Range.atLeast(0L), "NewAttribute", 11);
		}
		waitForSwing();

		assertPathIs(path, 0, 4);
	}

	@Test
	public void testPanesTrackRemoveElement() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		assertPathIsThreadsContainer();

		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceObject threads = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
			threads.setElement(Range.all(), 2, null);
		}
		waitForSwing();

		assertPathIs(path, 9, 0);
	}

	@Test
	public void testPanesTrackRemoveAttribute() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		assertPathIs(path, 0, 3);

		try (UndoableTransaction tid = tb.startTransaction()) {
			DBTraceObject thread = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
			thread.setAttribute(Range.all(), "_self", null);
		}
		waitForSwing();

		assertPathIs(path, 0, 2);
	}

	@Test
	public void testPanesTrackLifespanChangedElement() throws Throwable {
		modelProvider.setLimitToCurrentSnap(true);
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads");
		TraceObject threads = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
		TraceObjectValue element2 = threads.getElement(2, 2);

		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(2);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		assertPathIs(path, 3, 0);

		try (UndoableTransaction tid = tb.startTransaction()) {
			element2.setLifespan(Range.atLeast(10L), ConflictResolution.DENY);
		}
		waitForSwing();

		assertPathIs(path, 2, 0);

		try (UndoableTransaction tid = tb.startTransaction()) {
			element2.setLifespan(Range.atLeast(2L), ConflictResolution.DENY);
		}
		waitForSwing();

		assertPathIs(path, 3, 0);
	}

	@Test
	public void testPanesTrackLifespanChangedAttribute() throws Throwable {
		modelProvider.setLimitToCurrentSnap(true);
		modelProvider.setShowHidden(true);
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");
		TraceObject thread = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
		TraceObjectValue attrSelf = thread.getAttribute(2, "_self");

		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(2);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		assertPathIs(path, 0, 4); // _next created at snap 3

		try (UndoableTransaction tid = tb.startTransaction()) {
			attrSelf.setLifespan(Range.atLeast(10L), ConflictResolution.DENY);
		}
		waitForSwing();

		assertPathIs(path, 0, 3);

		try (UndoableTransaction tid = tb.startTransaction()) {
			attrSelf.setLifespan(Range.atLeast(2L), ConflictResolution.DENY);
		}
		waitForSwing();

		assertPathIs(path, 0, 4);
	}

	@Test
	public void testTreeTracksDisplayChange() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");
		TraceObject thread = tb.trace.getObjectManager().getObjectByCanonicalPath(path);

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForSwing();

		AbstractNode node =
			waitForValue(() -> modelProvider.objectsTreePanel.treeModel.getNode(path));
		assertEquals("<html>[2]", node.getDisplayText());

		try (UndoableTransaction tid = tb.startTransaction()) {
			thread.setAttribute(Range.atLeast(0L), "_display", "Renamed Thread");
		}
		waitForSwing();

		waitForPass(() -> assertEquals("<html>Renamed Thread", node.getDisplayText()));
	}
}
