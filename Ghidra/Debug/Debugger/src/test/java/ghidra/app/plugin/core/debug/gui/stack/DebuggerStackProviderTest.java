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

import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.List;

import org.junit.*;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DebuggerStackProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerStackPlugin stackPlugin;
	protected DebuggerStackProvider stackProvider;
	protected DebuggerStaticMappingService mappingService;

	protected Register pc;

	@Before
	public void setUpStackProviderTest() throws Exception {
		stackPlugin = addPlugin(tool, DebuggerStackPlugin.class);
		stackProvider = waitForComponentProvider(DebuggerStackProvider.class);

		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);

		pc = getToyBE64Language().getProgramCounter();
	}

	protected TraceThread addThread(String n) throws DuplicateNameException {
		try (UndoableTransaction tid = tb.startTransaction()) {
			return tb.trace.getThreadManager().createThread(n, 0);
		}
	}

	protected void addRegVals(TraceThread thread) {
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(pc, new BigInteger("00400123", 16)));
		}
	}

	protected TraceStack addStack(TraceThread thread, int snap) {
		try (UndoableTransaction tid = tb.startTransaction()) {
			return tb.trace.getStackManager().getStack(thread, snap, true);
		}
	}

	protected TraceStack addStack(TraceThread thread) {
		return addStack(thread, 0);
	}

	protected void addStackFrames(TraceStack stack) {
		try (UndoableTransaction tid = tb.startTransaction()) {
			stack.setDepth(2, false);

			TraceStackFrame frame = stack.getFrame(0, false);
			frame.setProgramCounter(tb.addr(0x00400100));
			frame.setComment("Hello");

			frame = stack.getFrame(1, false);
			frame.setProgramCounter(tb.addr(0x00400200));
			frame.setComment("World");
		}
	}

	protected void assertProviderEmpty() {
		List<StackFrameRow> framesDisplayed = stackProvider.stackTableModel.getModelData();
		assertTrue(framesDisplayed.isEmpty());
	}

	protected void assertProviderPopulatedSynthetic() {
		List<StackFrameRow> framesDisplayed = stackProvider.stackTableModel.getModelData();
		StackFrameRow row = Unique.assertOne(framesDisplayed);

		assertNull(row.frame);
		assertEquals(0x00400123, row.getProgramCounter().getOffset());
	}

	protected void assertTableSize(int size) {
		assertEquals(size, stackProvider.stackTableModel.getModelData().size());
	}

	protected void assertRow(int level, Address pcVal, String comment, Function func) {
		StackFrameRow row = stackProvider.stackTableModel.getModelData().get(level);
		assertEquals(level, row.getFrameLevel());
		assertNotNull(row.frame);
		assertEquals(pcVal, row.getProgramCounter());
		assertEquals(comment, row.getComment());
		assertEquals(func, row.getFunction());
	}

	protected void assertProviderPopulated() {
		assertTableSize(2);
		assertRow(0, tb.addr(0x00400100), "Hello", null);
		assertRow(1, tb.addr(0x00400200), "World", null);
	}

	@Test
	public void testEmpty() throws Exception {
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testActivateTraceNoThreadEmpty() throws Exception {
		createAndOpenTrace();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	public void testActivateThreadNoStackNoRegsEmpty() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	public void testActivateThreadNoStackRegsSynthetic() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		addRegVals(thread);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulatedSynthetic();
	}

	@Test
	public void testActivateThreadRegsThenAddEmptyStackEmpty() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		addRegVals(thread);
		addStack(thread);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	public void testActivateThreadThenAddStackPopulatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		traceManager.activateThread(thread);
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		assertProviderPopulated();
	}

	@Test
	public void testAddStackThenActivateThreadPopulatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();
	}

	@Test
	public void testAppendStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		try (UndoableTransaction tid = tb.startTransaction()) {
			stack.setDepth(3, false);
		}
		waitForDomainObject(tb.trace);

		assertTableSize(3);
		assertRow(0, tb.addr(0x00400100), "Hello", null);
		assertRow(1, tb.addr(0x00400200), "World", null);
		assertRow(2, null, null, null);
	}

	@Test
	public void testPushStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		try (UndoableTransaction tid = tb.startTransaction()) {
			stack.setDepth(3, true);
		}
		waitForDomainObject(tb.trace);

		assertTableSize(3);
		assertRow(0, null, null, null);
		assertRow(1, tb.addr(0x00400100), "Hello", null);
		assertRow(2, tb.addr(0x00400200), "World", null);
	}

	@Test
	public void testTruncateStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		try (UndoableTransaction tid = tb.startTransaction()) {
			stack.setDepth(1, false);
		}
		waitForDomainObject(tb.trace);

		assertTableSize(1);
		assertRow(0, tb.addr(0x00400100), "Hello", null);
	}

	@Test
	public void testPopStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		try (UndoableTransaction tid = tb.startTransaction()) {
			stack.setDepth(1, true);
		}
		waitForDomainObject(tb.trace);

		assertTableSize(1);
		assertRow(0, tb.addr(0x00400200), "World", null);
	}

	@Test
	public void testDeleteStackUpdatesProvider() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		try (UndoableTransaction tid = tb.startTransaction()) {
			stack.delete();
		}
		waitForDomainObject(tb.trace);

		assertProviderEmpty();
	}

	@Test
	public void testActivateOtherThread() throws Exception {
		createAndOpenTrace();

		TraceThread thread1 = addThread("Thread 1");
		TraceThread thread2 = addThread("Thread 2");
		TraceStack stack = addStack(thread1);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread1);
		waitForSwing();

		assertProviderPopulated();

		traceManager.activateThread(thread2);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	public void testActivateSnap() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		addStack(thread, 1);
		waitForSwing();

		assertProviderPopulated();

		traceManager.activateSnap(1);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	public void testCloseCurrentTraceEmpty() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		traceManager.closeTrace(tb.trace);
		waitForSwing();

		assertProviderEmpty();
	}

	@Test
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testSelectRowActivatesFrame() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		clickTableCellWithButton(stackProvider.stackTable, 0, 0, MouseEvent.BUTTON1);
		waitForSwing();

		assertEquals(0, traceManager.getCurrentFrame());

		clickTableCellWithButton(stackProvider.stackTable, 1, 0, MouseEvent.BUTTON1);
		waitForSwing();

		assertEquals(1, traceManager.getCurrentFrame());
	}

	@Test
	public void testActivateFrameSelectsRow() throws Exception {
		createAndOpenTrace();

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		traceManager.activateFrame(0);
		waitForSwing();

		assertEquals(0, stackProvider.stackTable.getSelectedRow());

		traceManager.activateFrame(1);
		waitForSwing();

		assertEquals(1, stackProvider.stackTable.getSelectedRow());
	}

	@Test
	public void testActivateThenAddMappingPopulatesFunctionColumn() throws Exception {
		createTrace();
		createProgramFromTrace();

		intoProject(tb.trace);
		intoProject(program);

		traceManager.openTrace(tb.trace);
		programManager.openProgram(program);

		TraceThread thread = addThread("Thread 1");
		TraceStack stack = addStack(thread);
		addStackFrames(stack);
		waitForDomainObject(tb.trace);

		traceManager.activateThread(thread);
		waitForSwing();

		assertProviderPopulated();

		Function func;
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add Function", true)) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00600000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			AddressSet body = new AddressSet();
			body.add(addr(program, 0x00600100), addr(program, 0x00600123));
			func = program.getFunctionManager()
					.createFunction("func", body.getMinAddress(), body, SourceType.USER_DEFINED);
		}
		waitForDomainObject(program);

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("bin:.text", Range.atLeast(0L), tb.drng(0x00400000, 0x00400fff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			TraceLocation dloc =
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x00400000));
			ProgramLocation sloc = new ProgramLocation(program, addr(program, 0x00600000));
			DebuggerStaticMappingUtils.addMapping(dloc, sloc, 0x1000, false);
		}
		waitForDomainObject(tb.trace);

		assertTableSize(2);
		assertRow(0, tb.addr(0x00400100), "Hello", func);
		assertRow(1, tb.addr(0x00400200), "World", null);
	}
}
