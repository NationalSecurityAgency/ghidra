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

import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;

import org.jdom.JDOMException;
import org.junit.*;

import db.Transaction;
import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
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
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;

public class DebuggerModelProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected static final SchemaContext CTX;

	static {
		try {
			CTX = XmlSchemaContext.deserialize("""
					<context>
					    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
					        <attribute name='Processes' schema='ProcessContainer' />
					        <interface name='EventScope' />
					    </schema>
					    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER'
					            attributeResync='ONCE'>
					        <element schema='Process' />
					    </schema>
					    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
					        <attribute name='Threads' schema='ThreadContainer' />
					        <attribute name='Handles' schema='HandleContainer' />
					    </schema>
					    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
					            attributeResync='ONCE'>
					        <element schema='Thread' />
					    </schema>
					    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
					        <interface name='Thread' />
					        <attribute name='_display' schema='STRING' />
					        <attribute name='_self' schema='Thread' />
					        <attribute name='Stack' schema='Stack' />
					    </schema>
					    <schema name='Stack' canonical='yes' elementResync='NEVER'
					            attributeResync='ONCE'>
					        <interface name='Stack' />
					        <element schema='Frame' />
					    </schema>
					    <schema name='Frame' elementResync='NEVER' attributeResync='NEVER'>
					        <interface name='StackFrame' />
					    </schema>
					    <schema name='HandleContainer' canonical='yes' elementResync='NEVER'
					            attributeResync='ONCE'>
					        <element schema='INT' />
					    </schema>
					</context>
					""");
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
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getTimeManager().getSnapshot(20, true);
		}
	}

	protected TraceObjectValue createSessionObject() throws Throwable {
		TraceObjectManager objects = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			return objects.createRootObject(CTX.getSchema(new SchemaName("Session")));
		}
	}

	protected TraceObject createThread(long i, TraceObject prevThread) {
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObjectKeyPath threadContainerPath = TraceObjectKeyPath.parse("Processes[0].Threads");
		TraceObject thread = objects.createObject(threadContainerPath.index(i));
		thread.insert(Lifespan.span(i, 10), ConflictResolution.DENY);
		thread.insert(Lifespan.nowOn(10 + i), ConflictResolution.DENY);
		thread.setAttribute(Lifespan.nowOn(i), "Attribute " + i, "Some value");
		thread.setAttribute(Lifespan.nowOn(i), "_display", "Thread " + i);
		thread.setAttribute(Lifespan.nowOn(i), "_self", thread);
		if (prevThread != null) {
			thread.setAttribute(Lifespan.nowOn(i), "_prev", prevThread);
			prevThread.setAttribute(Lifespan.nowOn(i), "_next", thread);
		}
		objects.getRootObject()
				.setAttribute(Lifespan.nowOn(i), TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME,
					thread);
		return thread;
	}

	protected TraceObject createStack(TraceObject thread) {
		try (Transaction tx = tb.startTransaction()) {
			TraceObjectKeyPath stackPath = thread.getCanonicalPath().key("Stack");
			TraceObjectManager objects = tb.trace.getObjectManager();
			TraceObject stack = objects.createObject(stackPath);
			objects.createObject(stackPath.index(0))
					.insert(thread.getLife().bound(), ConflictResolution.TRUNCATE);
			objects.createObject(stackPath.index(1))
					.insert(thread.getLife().bound(), ConflictResolution.TRUNCATE);
			return stack;
		}
	}

	protected void populateThreads() throws Throwable {
		try (Transaction tx = tb.startTransaction()) {
			TraceObject prevThread = null;
			for (long i = 0; i < 10; i++) {
				TraceObject thread = createThread(i, prevThread);
				prevThread = thread;
			}
		}
	}

	protected void addThread10() throws Throwable {
		TraceObjectManager objects = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			createThread(10, objects.getObjectByCanonicalPath(
				TraceObjectKeyPath.parse("Processes[0].Threads[9]")));
		}
	}

	protected void populateHandles() throws Throwable {
		TraceObjectManager objects = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			TraceObject handleContainer =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Handles"));
			handleContainer.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			for (int i = 0; i < 10; i++) {
				handleContainer.setElement(Lifespan.nowOn(-i), i,
					(i * 0xdeadbeef) % 0xbadc0de);
			}
		}
	}

	protected void populateLinks() throws Throwable {
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObjectKeyPath threadContainerPath = TraceObjectKeyPath.parse("Processes[0].Threads");
		try (Transaction tx = tb.startTransaction()) {
			TraceObject linkContainer =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Links"));
			linkContainer.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			for (int i = 0; i < 10; i++) {
				linkContainer.setElement(Lifespan.nowOn(0), i,
					objects.getObjectByCanonicalPath(threadContainerPath.index(9 - i)));
			}
		}
	}

	protected void populateBoxedPrimitive() throws Throwable {
		TraceObjectManager objects = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			TraceObject boxed =
				objects.createObject(TraceObjectKeyPath.parse("Processes[0].Boxed"));
			boxed.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			boxed.setAttribute(Lifespan.nowOn(2), TargetObject.DISPLAY_ATTRIBUTE_NAME, "2");
			boxed.setAttribute(Lifespan.nowOn(4), TargetObject.DISPLAY_ATTRIBUTE_NAME, "4");
		}
	}

	protected void createTraceAndPopulateObjects() throws Throwable {
		createAndOpenTrace();
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
		createAndOpenTrace();

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
		waitForTasks();
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
		waitForTasks();

		ValueRow selElem = waitForValue(() -> {
			List<ValueRow> rows = modelProvider.elementsTablePanel.tableModel.getModelData();
			if (rows.size() != 10) {
				return null;
			}
			return rows.get(2);
		});
		modelProvider.elementsTablePanel.setSelectedItem(selElem);
		waitForTasks();

		waitForPass(() -> assertEquals(3,
			modelProvider.attributesTablePanel.tableModel.getModelData().size()));
	}

	@Test
	public void testSetPathNoExist() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].NoSuch"));
		waitForTasks();

		assertEquals("No such object at path Processes[0].NoSuch", tool.getStatusInfo());
	}

	@Test
	public void testPrimitiveElements() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Handles"));
		waitForTasks();

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
		waitForTasks();

		modelProvider.pathField.setText("SomeNonsenseToBeCancelled");
		triggerEscapeKey(modelProvider.pathField);
		waitForSwing();

		assertPathIsThreadsContainer();
	}

	@Test
	public void testDoubleClickObjectInObjectsTree() throws Throwable {
		createTraceAndPopulateObjects();

		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObject root = objects.getRootObject();
		TraceObjectKeyPath processesPath = TraceObjectKeyPath.parse("Processes");
		TraceObject processes = objects.getObjectByCanonicalPath(processesPath);
		traceManager.activateObject(root);
		waitForTasks();

		modelProvider.setTreeSelection(processesPath, EventOrigin.USER_GENERATED);
		waitForSwing();

		GTree tree = modelProvider.objectsTreePanel.tree;
		GTreeNode node = waitForPass(() -> {
			GTreeNode n = Unique.assertOne(tree.getSelectedNodes());
			assertEquals("Processes", n.getName());
			return n;
		});
		clickTreeNode(tree, node, MouseEvent.BUTTON1);
		clickTreeNode(tree, node, MouseEvent.BUTTON1);
		waitForSwing();
		waitForPass(() -> assertEquals(processes, traceManager.getCurrentObject()));
	}

	@Test
	public void testDoubleClickLinkInElementsTable() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		TraceObjectKeyPath pathLinks = TraceObjectKeyPath.parse("Processes[0].Links");
		modelProvider.setPath(pathLinks);
		waitForTasks();

		ValueRow row2 = waitForValue(() -> {
			return modelProvider.elementsTablePanel.tableModel.getModelData()
					.stream()
					.filter(r -> r.getValue().getEntryKey().equals("[2]"))
					.findAny()
					.orElse(null);
		});
		modelProvider.elementsTablePanel.setSelectedItem(row2);
		waitForTasks();
		int rowIndex = waitForValue(() -> {
			int index = modelProvider.elementsTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.elementsTablePanel.table, rowIndex, 0, 2);

		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[7]"),
			traceManager.getCurrentObject().getCanonicalPath());
	}

	@Test
	public void testDoubleClickObjectInElementsTable() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForTasks();

		ValueRow row2 = waitForValue(() -> {
			return modelProvider.elementsTablePanel.tableModel.getModelData()
					.stream()
					.filter(r -> r.getValue().getEntryKey().equals("[2]"))
					.findAny()
					.orElse(null);
		});
		modelProvider.elementsTablePanel.setSelectedItem(row2);
		waitForTasks();
		int rowIndex = waitForValue(() -> {
			int index = modelProvider.elementsTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.elementsTablePanel.table, rowIndex, 0, 2);

		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[2]"),
			traceManager.getCurrentObject().getCanonicalPath());
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
		waitForTasks();
		selectAttribute("_next");
		waitForTasks();

		int rowIndex = waitForValue(() -> {
			int index = modelProvider.attributesTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.attributesTablePanel.table, rowIndex, 0, 2);

		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[3]"),
			traceManager.getCurrentObject().getCanonicalPath());
	}

	@Test
	public void testDoubleClickObjectInAttributesTable() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0]"));
		waitForTasks();

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
		waitForTasks();
		int rowIndex = waitForValue(() -> {
			int index = modelProvider.attributesTablePanel.table.getSelectedRow();
			if (index == -1) {
				return null;
			}
			return index;
		});
		clickTableCell(modelProvider.attributesTablePanel.table, rowIndex, 0, 2);

		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads"),
			traceManager.getCurrentObject().getCanonicalPath());
	}

	@Test
	public void testActionLimitToSnap() throws Throwable {
		assertFalse(modelProvider.isLimitToCurrentSnap());
		assertFalse(modelProvider.actionLimitToCurrentSnap.isSelected());
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads"));
		waitForTasks();

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
		TraceObjectKeyPath thread2Path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");
		modelProvider.setPath(thread2Path);
		modelProvider.setTreeSelection(thread2Path);
		waitForTasks();

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
		waitForTasks();
		selectAttribute("_next");
		waitForSwing();

		assertEnabled(modelProvider, modelProvider.actionFollowLink);
		performAction(modelProvider.actionFollowLink, modelProvider, true);

		TraceObjectKeyPath thread3Path = TraceObjectKeyPath.parse("Processes[0].Threads[3]");
		assertPathIs(thread3Path, 0, 5);
	}

	@Test
	public void testActionCloneWindow() throws Throwable {
		createTraceAndPopulateObjects();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads[2]"));
		waitForTasks();

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
		waitForTasks();

		assertPathIsThreadsContainer();

		addThread10();
		waitForTasks();

		assertPathIs(path, 11, 0);
	}

	@Test
	public void testPanesTrackAddAttribute() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForTasks();

		assertPathIs(path, 0, 3);

		try (Transaction tx = tb.startTransaction()) {
			TraceObject thread = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
			thread.setAttribute(Lifespan.nowOn(0), "NewAttribute", 11);
		}
		waitForTasks();

		assertPathIs(path, 0, 4);
	}

	@Test
	public void testPanesTrackRemoveElement() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForTasks();

		assertPathIsThreadsContainer();

		try (Transaction tx = tb.startTransaction()) {
			TraceObject threads = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
			threads.setElement(Lifespan.ALL, 2, null);
		}
		waitForTasks();

		assertPathIs(path, 9, 0);
	}

	@Test
	public void testPanesTrackRemoveAttribute() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectKeyPath path = TraceObjectKeyPath.parse("Processes[0].Threads[2]");

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		modelProvider.setPath(path);
		waitForTasks();

		assertPathIs(path, 0, 3);

		try (Transaction tx = tb.startTransaction()) {
			TraceObject thread = tb.trace.getObjectManager().getObjectByCanonicalPath(path);
			thread.setAttribute(Lifespan.ALL, "_self", null);
		}
		waitForTasks();

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
		waitForTasks();

		assertPathIs(path, 3, 0);

		try (Transaction tx = tb.startTransaction()) {
			element2.setLifespan(Lifespan.nowOn(10), ConflictResolution.DENY);
		}
		waitForTasks();

		assertPathIs(path, 2, 0);

		try (Transaction tx = tb.startTransaction()) {
			element2.setLifespan(Lifespan.nowOn(2), ConflictResolution.DENY);
		}
		waitForTasks();

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
		waitForTasks();

		assertPathIs(path, 0, 4); // _next created at snap 3

		try (Transaction tx = tb.startTransaction()) {
			attrSelf.setLifespan(Lifespan.nowOn(10), ConflictResolution.DENY);
		}
		waitForTasks();

		assertPathIs(path, 0, 3);

		try (Transaction tx = tb.startTransaction()) {
			attrSelf.setLifespan(Lifespan.nowOn(2), ConflictResolution.DENY);
		}
		waitForTasks();

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
		waitForTasks();

		AbstractNode node =
			waitForValue(() -> modelProvider.objectsTreePanel.treeModel.getNode(path));
		assertEquals("<html>[2]", node.getDisplayText());

		try (Transaction tx = tb.startTransaction()) {
			thread.setAttribute(Lifespan.nowOn(0), "_display", "Renamed Thread");
		}
		waitForTasks();

		waitForPass(() -> assertEquals("<html>Renamed Thread", node.getDisplayText()));
	}

	@Test
	public void testObjectActivationSelectsTree() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObject root = objects.getRootObject();
		TraceObject process0 =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Processes[0]"));

		traceManager.activateObject(root);
		waitForTasks();
		assertEquals(root, modelProvider.getTreeSelection().getChild());

		/**
		 * NOTE: Have to skip a level, lest is select the child in the attributes pane instead
		 */
		traceManager.activateObject(process0);
		waitForTasks();
		assertEquals(process0, modelProvider.getTreeSelection().getChild());
	}

	@Test
	public void testObjectActivationParentDoesNothing() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObject root = objects.getRootObject();
		TraceObject processes = root.getAttribute(0, "Processes").getChild();

		traceManager.activateObject(processes);
		waitForTasks();
		modelProvider.setTreeSelection(processes.getCanonicalPath());
		waitForSwing();

		traceManager.activateObject(root);
		waitForTasks();
		// TODO: Is this the desired behavior?
		assertEquals(processes, modelProvider.getTreeSelection().getChild());
	}

	@Test
	public void testObjectActivationSiblingSelectsTree() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObject thread0 =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Processes[0].Threads[0]"));
		TraceObject thread1 =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Processes[0].Threads[1]"));

		modelProvider.setShowHidden(true);
		traceManager.activateObject(thread0);
		traceManager.activateSnap(1);
		waitForTasks();
		modelProvider.setPath(TraceObjectKeyPath.parse("Processes[0].Threads[0]._self"));
		waitForTasks();

		traceManager.activateObject(thread1);
		waitForSwing();
		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[0]._next"),
			modelProvider.getPath());
	}

	@Test
	public void testObjectActivationSelectsElement() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObjectKeyPath processesPath = TraceObjectKeyPath.parse("Processes");
		TraceObject processes = objects.getObjectByCanonicalPath(processesPath);
		TraceObject process0 = processes.getElement(0, 0).getChild();
		traceManager.activateObject(processes);
		waitForTasks();

		/**
		 * TODO: It's interesting that activating a parent then a child produces a different end
		 * result than activating the child directly.
		 */
		traceManager.activateObject(process0);
		waitForTasks();

		assertEquals(processesPath, modelProvider.getPath());
		assertEquals(process0,
			modelProvider.elementsTablePanel.getSelectedItem().getValue().getChild());
	}

	@Test
	public void testObjectActivationSelectsAttribute() throws Throwable {
		createTraceAndPopulateObjects();
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObject root = objects.getRootObject();
		TraceObject processes = root.getAttribute(0, "Processes").getChild();
		traceManager.activateObject(root);
		waitForTasks();
		// Warm it up a bit. TODO: This is kind of cheating.
		traceManager.activateObject(processes);
		waitForTasks();
		traceManager.activateObject(root);
		modelProvider.setPath(root.getCanonicalPath());
		waitForTasks();

		/**
		 * TODO: It's interesting that activating a parent then a child produces a different end
		 * result than activating the child directly.
		 */
		traceManager.activateObject(processes);
		waitForTasks();

		assertEquals(TraceObjectKeyPath.of(), modelProvider.getPath());
		assertEquals(processes, modelProvider.attributesTablePanel.getSelectedItem().getValue());
	}

	protected TraceThread populateThread0Stack() {
		TraceObjectManager objects = tb.trace.getObjectManager();
		TraceObject threadObj0 =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Processes[0].Threads[0]"));
		TraceThread thread0 = threadObj0.queryInterface(TraceObjectThread.class);
		createStack(threadObj0);
		return thread0;
	}

	@Test
	public void testFrameActivationSelectsSibling() throws Throwable {
		createTraceAndPopulateObjects();
		TraceThread thread0 = populateThread0Stack();

		traceManager.activate(DebuggerCoordinates.NOWHERE.thread(thread0).frame(0));
		waitForSwing();
		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[0].Stack[0]"),
			modelProvider.getPath());

		traceManager.activateFrame(1);
		waitForSwing();
		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[0].Stack[1]"),
			modelProvider.getPath());
	}

	@Test
	public void testFrameActivationSelectsElement() throws Throwable {
		createTraceAndPopulateObjects();
		TraceThread thread0 = populateThread0Stack();
		TraceObjectKeyPath stackPath = TraceObjectKeyPath.parse("Processes[0].Threads[0].Stack");

		traceManager.activateThread(thread0);
		waitForSwing();
		modelProvider.setPath(stackPath);
		waitForTasks();

		// Test 1 then 0, because 0 is default
		traceManager.activateFrame(1);
		waitForTasks();
		assertEquals(stackPath, modelProvider.getPath());
		assertEquals(stackPath.index(1),
			modelProvider.elementsTablePanel.getSelectedItem().getValue().getCanonicalPath());

		traceManager.activateFrame(0);
		waitForTasks();
		assertEquals(stackPath, modelProvider.getPath());
		assertEquals(stackPath.index(0),
			modelProvider.elementsTablePanel.getSelectedItem().getValue().getCanonicalPath());
	}

	@Test
	public void testThreadActivationSelectsSibling() throws Throwable {
		createTraceAndPopulateObjects();
		TraceThread thread0 =
			tb.trace.getThreadManager().getLiveThreadByPath(1, "Processes[0].Threads[0]");
		TraceThread thread1 =
			tb.trace.getThreadManager().getLiveThreadByPath(1, "Processes[0].Threads[1]");

		traceManager.activateThread(thread0);
		traceManager.activateSnap(1);
		waitForSwing();
		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[0]"), modelProvider.getPath());

		traceManager.activateThread(thread1);
		waitForSwing();
		assertEquals(TraceObjectKeyPath.parse("Processes[0].Threads[1]"), modelProvider.getPath());
	}

	@Test
	public void testThreadActivationSelectsElement() throws Throwable {
		createTraceAndPopulateObjects();
		TraceThread thread0 =
			tb.trace.getThreadManager().getLiveThreadByPath(1, "Processes[0].Threads[0]");
		TraceThread thread1 =
			tb.trace.getThreadManager().getLiveThreadByPath(1, "Processes[0].Threads[1]");
		TraceObjectKeyPath threadsPath = TraceObjectKeyPath.parse("Processes[0].Threads");

		traceManager.activateTrace(tb.trace);
		traceManager.activateSnap(1);
		waitForSwing();

		modelProvider.setPath(threadsPath);
		waitForTasks();

		// Testing 1 then 0, because 0 is default
		traceManager.activateThread(thread1);
		waitForSwing();
		assertEquals(threadsPath, modelProvider.getPath());
		assertEquals(threadsPath.index(1),
			modelProvider.elementsTablePanel.getSelectedItem().getValue().getCanonicalPath());

		traceManager.activateThread(thread0);
		waitForSwing();
		assertEquals(threadsPath, modelProvider.getPath());
		assertEquals(threadsPath.index(0),
			modelProvider.elementsTablePanel.getSelectedItem().getValue().getCanonicalPath());
	}
}
