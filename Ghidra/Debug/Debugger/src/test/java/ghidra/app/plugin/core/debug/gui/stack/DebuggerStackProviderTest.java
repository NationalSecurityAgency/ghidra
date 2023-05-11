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
package ghidra.app.plugin.core.debug.gui.stack;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import org.junit.*;

import db.Transaction;
import docking.widgets.table.DynamicTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.QueryPanelTestHelper;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.util.task.TaskMonitor;

/**
 * NOTE: I no longer synthesize a stack frame when the stack is absent. It's a bit of a hack, and I
 * don't know if it's really valuable. In fact, in might obscure the fact that the stack is absent.
 */
public class DebuggerStackProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerStackPlugin stackPlugin;
	protected DebuggerStackProvider stackProvider;
	protected DebuggerStaticMappingService mappingService;

	protected Register pc;

	protected SchemaContext ctx;

	@Before
	public void setUpStackProviderTest() throws Exception {
		stackPlugin = addPlugin(tool, DebuggerStackPlugin.class);
		stackProvider = waitForComponentProvider(DebuggerStackProvider.class);

		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);

		pc = getToyBE64Language().getProgramCounter();
	}

	@After
	public void tearDownStackProviderTest() throws Exception {
		traceManager.activate(DebuggerCoordinates.NOWHERE);
		waitForSwing();
		waitForTasks();
		runSwing(() -> traceManager.closeAllTraces());
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
				        <element schema='Process' />
				    </schema>
				    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Threads' schema='ThreadContainer' />
				        <attribute name='Memory' schema='RegionContainer' />
				    </schema>
				    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Thread' />
				    </schema>
				    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Thread' />
				        <interface name='Aggregate' />
				        <attribute name='Stack' schema='Stack' />
				        <attribute name='Registers' schema='RegisterContainer' />
				    </schema>
				    <schema name='Stack' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <interface name='Stack' />
				        <element schema='Frame' />
				    </schema>
				    <schema name='Frame' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='StackFrame' />
				    </schema>
				    <schema name='RegisterContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='NEVER'>
				        <interface name='RegisterContainer' />
				        <element schema='Register' />
				    </schema>
				    <schema name='Register' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Register' />
				    </schema>
				    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Region' />
				    </schema>
				    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='MemoryRegion' />
				    </schema>
				</context>
				""");

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	protected TraceObjectThread addThread(int n) {
		PathPattern threadPattern = new PathPattern(PathUtils.parse("Processes[1].Threads[]"));
		TraceObjectKeyPath threadPath =
			TraceObjectKeyPath.of(threadPattern.applyIntKeys(n).getSingletonPath());
		try (Transaction tx = tb.startTransaction()) {
			return Objects.requireNonNull(tb.trace.getObjectManager()
					.createObject(threadPath)
					.insert(Lifespan.nowOn(0), ConflictResolution.TRUNCATE)
					.getDestination(null)
					.queryInterface(TraceObjectThread.class));
		}
	}

	protected TraceObjectStack addStack(TraceObjectThread thread) {
		TraceObjectKeyPath stackPath = thread.getObject().getCanonicalPath().extend("Stack");
		try (Transaction tx = tb.startTransaction()) {
			return Objects.requireNonNull(tb.trace.getObjectManager()
					.createObject(stackPath)
					.insert(Lifespan.nowOn(0), ConflictResolution.TRUNCATE)
					.getDestination(null)
					.queryInterface(TraceObjectStack.class));
		}
	}

	protected void addStackFrames(TraceObjectStack stack) {
		addStackFrames(stack, 2);
	}

	protected void addStackFrames(TraceObjectStack stack, int count) {
		TraceObjectKeyPath stackPath = stack.getObject().getCanonicalPath();
		TraceObjectManager om = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			for (int i = 0; i < count; i++) {
				TraceObject frame = om.createObject(stackPath.index(i))
						.insert(Lifespan.nowOn(0), ConflictResolution.TRUNCATE)
						.getDestination(null);
				frame.setAttribute(Lifespan.nowOn(0), TargetStackFrame.PC_ATTRIBUTE_NAME,
					tb.addr(0x00400100 + 0x100 * i));
			}
		}
	}

	protected void assertProviderEmpty() {
		assertTrue(stackProvider.panel.getAllItems().isEmpty());
	}

	protected void assertTableSize(int size) {
		assertEquals(size, stackProvider.panel.getAllItems().size());
	}

	protected void assertRow(int level, Address pcVal, Function func) {
		ValueRow row = stackProvider.panel.getAllItems().get(level);

		DynamicTableColumn<ValueRow, String, Trace> levelCol =
			stackProvider.panel.getColumnByNameAndType("Level", String.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> pcCol =
			stackProvider.panel.getColumnByNameAndType("PC", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, Function, Trace> funcCol =
			stackProvider.panel.getColumnByNameAndType("Function", Function.class).getValue();

		assertEquals(PathUtils.makeKey(PathUtils.makeIndex(level)), rowColVal(row, levelCol));
		assertEquals(pcVal, rowColVal(row, pcCol));
		assertEquals(func, rowColVal(row, funcCol));
	}

	protected void assertProviderPopulated() {
		assertTableSize(2);
		assertRow(0, tb.addr(0x00400100), null);
		assertRow(1, tb.addr(0x00400200), null);
	}

	@Test
	public void testEmpty() throws Exception {
		waitForSwing();
		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateTraceNoThreadEmpty() throws Exception {
		createAndOpenTrace();

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateThreadNoStackEmpty() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateThreadThenAddEmptyStackEmpty() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		addStack(thread);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateThreadThenAddStackPopulatesProvider() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		traceManager.activateObject(thread.getObject());
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());
	}

	@Test
	public void testAddStackThenActivateThreadPopulatesProvider() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());
	}

	/**
	 * Because keys are strings, we need to ensure they get sorted numerically
	 * 
	 * @throws Exception
	 */
	@Test
	public void testTableSortedCorrectly() throws Exception {
		createAndOpenTrace();
		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack, 15);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(15);
			List<ValueRow> allItems = stackProvider.panel.getAllItems();
			for (int i = 0; i < 15; i++) {
				assertEquals(PathUtils.makeKey(PathUtils.makeIndex(i)), allItems.get(i).getKey());
			}
		});
	}

	@Test
	public void testAppendStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		try (Transaction tx = tb.startTransaction()) {
			TraceObject frame2 = tb.trace.getObjectManager()
					.createObject(stack.getObject().getCanonicalPath().index(2))
					.insert(Lifespan.nowOn(0), ConflictResolution.TRUNCATE)
					.getDestination(null);
			frame2.setAttribute(Lifespan.nowOn(0), TargetStackFrame.PC_ATTRIBUTE_NAME,
				tb.addr(0x00400300));
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(3);
			assertRow(0, tb.addr(0x00400100), null);
			assertRow(1, tb.addr(0x00400200), null);
			assertRow(2, tb.addr(0x00400300), null);
		});
	}

	@Test
	public void testRemoveFrameUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		try (Transaction tx = tb.startTransaction()) {
			TraceObject frame1 = stack.getObject().getElement(0, 1).getChild();
			frame1.removeTree(Lifespan.nowOn(0));
		}
		waitForDomainObject(tb.trace);
		waitForTasks();
		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, tb.addr(0x00400100), null);
		});
	}

	@Test
	public void testRemoveStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		try (Transaction tx = tb.startTransaction()) {
			stack.getObject().removeTree(Lifespan.nowOn(0));
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateOtherThreadEmptiesProvider() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread1 = addThread(1);
		TraceObjectThread thread2 = addThread(2);
		TraceObjectStack stack1 = addStack(thread1);
		addStackFrames(stack1);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread1.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		traceManager.activateObject(thread2.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateSnap() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		try (Transaction tx = tb.startTransaction()) {
			stack.getObject().removeTree(Lifespan.nowOn(1));
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		traceManager.activateSnap(1);
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());

		traceManager.activateSnap(0);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());
	}

	@Test
	public void testCloseCurrentTraceEmpty() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		traceManager.closeTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateFrameSelectsRow() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		TraceObject frame0 = stack.getObject().getElement(0, 0).getChild();
		TraceObject frame1 = stack.getObject().getElement(0, 1).getChild();
		List<ValueRow> allItems = stackProvider.panel.getAllItems();

		traceManager.activateObject(frame1);
		waitForTasks();
		waitForPass(() -> assertEquals(allItems.get(1), stackProvider.panel.getSelectedItem()));

		traceManager.activateObject(frame0);
		waitForTasks();
		waitForPass(() -> assertEquals(allItems.get(0), stackProvider.panel.getSelectedItem()));
	}

	@Test
	public void testDoubleClickRowActivateFrame() throws Exception {
		createAndOpenTrace();

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		TraceObject frame0 = stack.getObject().getElement(0, 0).getChild();
		TraceObject frame1 = stack.getObject().getElement(0, 1).getChild();

		clickTableCell(QueryPanelTestHelper.getTable(stackProvider.panel), 1, 0, 2);
		waitForTasks();
		waitForPass(() -> assertEquals(frame1, traceManager.getCurrentObject()));

		clickTableCell(QueryPanelTestHelper.getTable(stackProvider.panel), 0, 0, 2);
		waitForTasks();
		waitForPass(() -> assertEquals(frame0, traceManager.getCurrentObject()));
	}

	@Test
	public void testActivateTheAddMappingPopulatesFunctionColumn() throws Exception {
		createTrace();
		createProgramFromTrace();

		intoProject(tb.trace);
		intoProject(program);

		traceManager.openTrace(tb.trace);
		programManager.openProgram(program);

		TraceObjectThread thread = addThread(1);
		TraceObjectStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateObject(thread.getObject());
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		Function func;
		try (Transaction tx = program.openTransaction("Add Function")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00600000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			AddressSet body = new AddressSet();
			body.add(addr(program, 0x00600100), addr(program, 0x00600123));
			func = program.getFunctionManager()
					.createFunction("func", body.getMinAddress(), body, SourceType.USER_DEFINED);
		}
		waitForDomainObject(program);

		try (Transaction tx = tb.startTransaction()) {
			TraceObjectMemoryRegion region = Objects.requireNonNull(tb.trace.getObjectManager()
					.createObject(TraceObjectKeyPath.parse("Processes[1].Memory[bin:.text]"))
					.insert(Lifespan.nowOn(0), ConflictResolution.TRUNCATE)
					.getDestination(null)
					.queryInterface(TraceObjectMemoryRegion.class));
			region.getObject()
					.setAttribute(Lifespan.nowOn(0), TargetMemoryRegion.RANGE_ATTRIBUTE_NAME,
						tb.drng(0x00400000, 0x00400fff));

			TraceLocation dloc =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation sloc = new ProgramLocation(program, addr(program, 0x00600000));
			DebuggerStaticMappingUtils.addMapping(dloc, sloc, 0x1000, false);
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(2);
			assertRow(0, tb.addr(0x00400100), func);
			assertRow(1, tb.addr(0x00400200), null);
		});
	}
}
