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
package ghidra.app.plugin.core.debug.gui.watch;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.*;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncTestUtils;
import ghidra.dbg.model.TestTargetRegisterBankInThread;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;

public class DebuggerWatchesProviderTest extends AbstractGhidraHeadedDebuggerGUITest
		implements AsyncTestUtils {

	protected static void assertNoErr(WatchRow row) {
		Throwable error = row.getError();
		if (error != null) {
			throw new AssertionError(error);
		}
	}

	protected DebuggerWatchesPlugin watchesPlugin;
	protected DebuggerWatchesProvider watchesProvider;
	protected DebuggerListingPlugin listingPlugin;

	protected Register r0;
	protected Register r1;
	protected TraceThread thread;

	protected TestTargetRegisterBankInThread bank;
	protected TraceRecorder recorder;

	@Before
	public void setUpWatchesProviderTest() throws Exception {
		watchesPlugin = addPlugin(tool, DebuggerWatchesPlugin.class);
		watchesProvider = waitForComponentProvider(DebuggerWatchesProvider.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);

		createTrace();
		r0 = tb.language.getRegister("r0");
		r1 = tb.language.getRegister("r1");
		try (UndoableTransaction tid = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread1", 0);
		}
	}

	@After
	public void tearDownWatchesProviderTest() throws Exception {
		for (WatchRow row : watchesProvider.watchTableModel.getModelData()) {
			Throwable error = row.getError();
			if (error != null) {
				Msg.info(this, "Error on watch row: ", error);
			}
		}
	}

	private void setRegisterValues(TraceThread thread) {
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regVals =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regVals.setValue(0, new RegisterValue(r0, BigInteger.valueOf(0x00400000)));
		}
	}

	@Test
	public void testAddValsAddWatchThenActivateThread() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0");

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0x400000", row.getRawValueString());
		assertEquals("", row.getValueString()); // NB. No data type set
		assertNoErr(row);
	}

	@Test
	public void testActivateThreadAddWatchThenAddVals() {
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0");

		setRegisterValues(thread);

		waitForPass(() -> assertEquals("0x400000", row.getRawValueString()));
		assertNoErr(row);
	}

	@Test
	public void testWatchWithDataType() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0");
		row.setDataType(LongLongDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0x400000", row.getRawValueString());
		assertEquals("400000h", row.getValueString());
		assertNoErr(row);

		assertEquals(r0.getAddress(), row.getAddress());
		assertEquals(TraceRegisterUtils.rangeForRegister(r0), row.getRange());
	}

	@Test
	public void testConstantWatch() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("0xdeadbeef:4");
		row.setDataType(LongDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0xdeadbeef", row.getRawValueString());
		assertEquals("DEADBEEFh", row.getValueString());
		assertNoErr(row);

		Address constDeadbeef = tb.trace.getBaseAddressFactory().getConstantAddress(0xdeadbeefL);
		assertEquals(constDeadbeef, row.getAddress());
		assertEquals(new AddressRangeImpl(constDeadbeef, constDeadbeef), row.getRange());
	}

	@Test
	public void testUniqueWatch() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0 + 8");
		row.setDataType(LongLongDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0x400008", row.getRawValueString());
		assertEquals("400008h", row.getValueString());
		assertNoErr(row);

		assertNull(row.getAddress());
		assertNull(row.getRange());
	}

	@Test
	public void testLiveCausesReads() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		bank = mb.testThread1.addRegisterBank();

		// Write before we record, and verify trace has not recorded it before setting watch
		mb.testProcess1.regs.addRegistersFromLanguage(tb.language, Register::isBaseRegister);
		bank.writeRegister("r0", tb.arr(0, 0, 0, 0, 0, 0x40, 0, 0));
		mb.testProcess1.addRegion(".header", mb.rng(0, 0x1000), "r"); // Keep the listing away
		mb.testProcess1.addRegion(".text", mb.rng(0x00400000, 0x00401000), "rx");
		mb.testProcess1.memory.writeMemory(mb.addr(0x00400000), tb.arr(1, 2, 3, 4));

		recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));

		traceManager.openTrace(trace);
		traceManager.activateThread(thread);
		waitForSwing();

		// Verify no target read has occurred yet
		TraceMemoryRegisterSpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		if (regs != null) {
			assertEquals(BigInteger.ZERO, regs.getValue(0, r0).getUnsignedValue());
		}
		ByteBuffer buf = ByteBuffer.allocate(4);
		assertEquals(4, trace.getMemoryManager().getBytes(0, tb.addr(0x00400000), buf));
		assertArrayEquals(tb.arr(0, 0, 0, 0), buf.array());

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("*:4 r0");
		row.setDataType(LongDataType.dataType);

		waitForPass(() -> {
			if (row.getError() != null) {
				ExceptionUtils.rethrow(row.getError());
			}
			assertEquals("{ 01 02 03 04 }", row.getRawValueString());
			assertEquals("1020304h", row.getValueString());
		});
		assertNoErr(row);
	}

	protected void runTestDeadIsEditable(String expression, boolean expectWritable) {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression(expression);

		assertFalse(row.isValueEditable());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertNoErr(row);
		assertFalse(row.isValueEditable());

		performAction(watchesProvider.actionEnableEdits);
		assertEquals(expectWritable, row.isValueEditable());
	}

	@Test
	public void testDeadIsRegisterEditable() {
		runTestDeadIsEditable("r0", true);
	}

	@Test
	public void testDeadIsUniqueEditable() {
		runTestDeadIsEditable("r0 + 8", false);
	}

	@Test
	public void testDeadIsMemoryEditable() {
		runTestDeadIsEditable("*:8 r0", true);
	}

	protected WatchRow prepareTestDeadEdit(String expression) {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression(expression);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		performAction(watchesProvider.actionEnableEdits);

		return row;
	}

	@Test
	public void testDeadEditRegister() {
		WatchRow row = prepareTestDeadEdit("r0");

		row.setRawValueString("0x1234");
		waitForSwing();

		TraceMemoryRegisterSpace regVals =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertEquals(BigInteger.valueOf(0x1234), regVals.getValue(0, r0).getUnsignedValue());

		row.setRawValueString("1234");
		waitForSwing();

		assertEquals(BigInteger.valueOf(1234), regVals.getValue(0, r0).getUnsignedValue());
	}

	@Test
	public void testDeadEditMemory() {
		WatchRow row = prepareTestDeadEdit("*:8 r0");

		row.setRawValueString("0x1234");
		waitForSwing();

		TraceMemoryOperations mem = tb.trace.getMemoryManager();
		ByteBuffer buf = ByteBuffer.allocate(8);
		mem.getBytes(0, tb.addr(0x00400000), buf);
		buf.flip();
		assertEquals(0x1234, buf.getLong());

		row.setRawValueString("{ 12 34 56 78 9a bc de f0 }");
		waitForSwing();
		buf.clear();
		mem.getBytes(0, tb.addr(0x00400000), buf);
		buf.flip();
		assertEquals(0x123456789abcdef0L, buf.getLong());
	}

	protected WatchRow prepareTestLiveEdit(String expression) throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		bank = mb.testThread1.addRegisterBank();

		mb.testProcess1.regs.addRegistersFromLanguage(tb.language,
			r -> r != r1 && r.isBaseRegister());
		bank.writeRegister("r0", tb.arr(0, 0, 0, 0, 0, 0x40, 0, 0));
		mb.testProcess1.addRegion(".text", mb.rng(0x00400000, 0x00401000), "rx");

		recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));

		traceManager.openTrace(trace);
		traceManager.activateThread(thread);
		waitForSwing();

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression(expression);
		performAction(watchesProvider.actionEnableEdits);

		return row;
	}

	@Test
	public void testLiveEditRegister() throws Throwable {
		WatchRow row = prepareTestLiveEdit("r0");

		row.setRawValueString("0x1234");
		retryVoid(() -> {
			assertArrayEquals(tb.arr(0, 0, 0, 0, 0, 0, 0x12, 0x34), bank.regVals.get("r0"));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testLiveEditMemory() throws Throwable {
		WatchRow row = prepareTestLiveEdit("*:8 r0");

		row.setRawValueString("0x1234");
		retryVoid(() -> {
			assertArrayEquals(tb.arr(0, 0, 0, 0, 0, 0, 0x12, 0x34),
				waitOn(mb.testProcess1.memory.readMemory(tb.addr(0x00400000), 8)));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testLiveEditNonMappableRegister() throws Throwable {
		WatchRow row = prepareTestLiveEdit("r1");
		TraceThread thread = recorder.getTraceThread(mb.testThread1);

		// Sanity check
		assertFalse(recorder.isRegisterOnTarget(thread, r1));

		row.setRawValueString("0x1234");
		waitForSwing();

		TraceMemoryRegisterSpace regs =
			recorder.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regs.getValue(recorder.getSnap(), r1).getUnsignedValue());

		assertFalse(bank.regVals.containsKey("r1"));
	}
}
