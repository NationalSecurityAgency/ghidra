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
package ghidra.app.plugin.core.debug.service.model;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Map.Entry;

import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.TestTargetMemoryRegion;
import ghidra.dbg.model.TestTargetRegisterBankInThread;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceCodeRegisterSpace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public class DefaultTraceRecorderTest extends AbstractGhidraHeadedDebuggerGUITest {

	@Test
	public void testThreadsRecorded() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		waitForPass(() -> {
			assertNotNull(recorder.getTraceThread(mb.testThread1));
			assertNotNull(recorder.getTraceThread(mb.testThread2));
		});
	}

	@Test
	public void testRegionsRecorded() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		TestTargetMemoryRegion targetRegion =
			mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x5555ffff), "rx");

		waitForPass(() -> {
			assertNotNull(trace.getMemoryManager()
					.getLiveRegionByPath(recorder.getSnap(),
						PathUtils.toString(targetRegion.getPath())));
		});
	}

	protected TraceMemoryRegisterSpace createRegSpace(TraceThread thread) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(thread.getTrace(), "Create register space", true)) {
			return thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, true);
		}
	}

	protected boolean registerMapped(TraceRecorder recorder, TraceThread thread,
			Register register) {
		DebuggerRegisterMapper rm = recorder.getRegisterMapper(thread);
		if (rm == null) {
			return false;
		}
		return null != rm.traceToTarget(register);
	}

	@Test
	public void testHandlesWrongLengthRegValsGracefully() throws Exception {
		createTestModel();
		createTrace(); // Silly. Just to get tb.arr?
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register r0 = lang.getRegister("r0");
		Register r1 = lang.getRegister("r1");
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		//TraceThread thread = recorder.getTraceThread(mb.testThread1);
		TraceMemoryRegisterSpace rs = createRegSpace(thread);
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();

		//waitForCondition(() -> registerMapped(recorder, thread, r0));
		regs.writeRegister("r0", tb.arr(1)).get();

		waitForPass(() -> {
			assertEquals(BigInteger.ONE, rs.getValue(recorder.getSnap(), r0).getUnsignedValue());
		});

		regs.writeRegister("r1", tb.arr(1, 2, 3, 4, 5, 6, 7, 8, 9)).get();

		waitForPass(() -> {
			assertEquals(BigInteger.valueOf(0x02030405_06070809L),
				rs.getValue(recorder.getSnap(), r1).getUnsignedValue());
		});
	}

	@Test
	public void testUpdateRegsMemIgnoresNullSpVal() throws Exception {
		createTestModel();
		createTrace(); // Silly. Just to get tb.arr?
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register pc = lang.getRegister("pc");
		Register sp = lang.getRegister("sp");
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		TraceMemoryRegisterSpace rs = createRegSpace(thread);
		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x5555ffff), "rx");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			r -> r.isBaseRegister() && r != pc && r != sp);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add PC type", true)) {
			TraceCodeRegisterSpace code = trace.getCodeManager().getCodeRegisterSpace(thread, true);
			code.definedData().create(Range.atLeast(0L), pc, PointerDataType.dataType);
		}

		assertNull(rs.getMostRecentStateEntry(recorder.getSnap(), pc.getAddress()));
		assertNull(rs.getMostRecentStateEntry(recorder.getSnap(), sp.getAddress()));

		mb.testProcess1.regs.addRegister(pc);
		//waitForCondition(() -> registerMapped(recorder, thread, pc));
		regs.writeRegister("pc", tb.arr(0x55, 0x55, 0x01, 0x23));

		waitForPass(() -> {
			assertEquals(BigInteger.valueOf(0x55550123),
				rs.getValue(recorder.getSnap(), pc).getUnsignedValue());
		});

		assertNull(rs.getMostRecentStateEntry(recorder.getSnap(), sp.getAddress()));

		TraceMemoryManager mm = trace.getMemoryManager();
		waitForPass(() -> {
			Entry<TraceAddressSnapRange, TraceMemoryState> ent =
				mm.getMostRecentStateEntry(recorder.getSnap(), tb.addr(0x55550123));
			assertNotNull(ent);
			assertEquals(TraceMemoryState.KNOWN, ent.getValue());
		});

		// Don't let null's get interpreted as 0
		assertNull(mm.getMostRecentStateEntry(recorder.getSnap(), tb.addr(0)));
	}

	@Test
	public void testUpdateRegsMemIgnoresNullPcVal() throws Exception {
		createTestModel();
		createTrace(); // Silly. Just to get tb.arr?
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register pc = lang.getRegister("pc");
		Register sp = lang.getRegister("sp");
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		TraceMemoryRegisterSpace rs = createRegSpace(thread);
		mb.testProcess1.addRegion("[stack]", mb.rng(0x22220000, 0x2222ffff), "rw");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			r -> r.isBaseRegister() && r != pc && r != sp);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add SP type", true)) {
			TraceCodeRegisterSpace code = trace.getCodeManager().getCodeRegisterSpace(thread, true);
			code.definedData().create(Range.atLeast(0L), sp, PointerDataType.dataType);
		}

		assertNull(rs.getMostRecentStateEntry(recorder.getSnap(), pc.getAddress()));
		assertNull(rs.getMostRecentStateEntry(recorder.getSnap(), sp.getAddress()));

		mb.testProcess1.regs.addRegister(sp);
		//waitForCondition(() -> registerMapped(recorder, thread, sp));
		regs.writeRegister("sp", tb.arr(0x22, 0x22, 0x03, 0x21));

		waitForPass(() -> {
			assertEquals(BigInteger.valueOf(0x22220321),
				rs.getValue(recorder.getSnap(), sp).getUnsignedValue());
		});

		assertNull(rs.getMostRecentStateEntry(recorder.getSnap(), pc.getAddress()));

		TraceMemoryManager mm = trace.getMemoryManager();
		waitForPass(() -> {
			Entry<TraceAddressSnapRange, TraceMemoryState> ent =
				mm.getMostRecentStateEntry(recorder.getSnap(), tb.addr(0x22220321));
			assertNotNull(ent);
			assertEquals(TraceMemoryState.KNOWN, ent.getValue());
		});

		// Don't let PC's null get interpreted as 0
		assertNull(mm.getMostRecentStateEntry(recorder.getSnap(), tb.addr(0)));
	}

	@Test
	public void testUpdatRegsMemStaysInRegions() throws Exception {
		createTestModel();
		createTrace(); // Silly. Just to get tb.arr?
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register pc = lang.getRegister("pc");
		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550123, 0x55550321), "rx");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();

		//waitForCondition(() -> registerMapped(recorder, thread, pc));
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add PC type", true)) {
			TraceCodeRegisterSpace code = trace.getCodeManager().getCodeRegisterSpace(thread, true);
			code.definedData().create(Range.atLeast(0L), pc, PointerDataType.dataType);
		}
		regs.writeRegister("pc", tb.arr(0x55, 0x55, 0x02, 0x22));

		TraceMemoryManager mm = trace.getMemoryManager();
		waitForPass(() -> {
			Entry<TraceAddressSnapRange, TraceMemoryState> ent =
				mm.getMostRecentStateEntry(recorder.getSnap(), tb.addr(0x55550222));
			assertNotNull(ent);
			assertEquals(TraceMemoryState.KNOWN, ent.getValue());
			assertEquals(tb.range(0x55550123, 0x55550321), ent.getKey().getRange());
		});
	}
}
