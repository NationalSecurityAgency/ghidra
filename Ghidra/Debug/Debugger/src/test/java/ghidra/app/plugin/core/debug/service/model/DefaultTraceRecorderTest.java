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

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.services.ActionSource;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.model.TestTargetMemoryRegion;
import ghidra.dbg.model.TestTargetRegisterBankInThread;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.*;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.thread.TraceThread;

public class DefaultTraceRecorderTest extends AbstractGhidraHeadedDebuggerGUITest {

	@Test
	public void testThreadsRecorded() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
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
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();

		TestTargetMemoryRegion targetRegion =
			mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x5555ffff), "rx");

		waitForPass(() -> {
			assertNotNull(trace.getMemoryManager()
					.getLiveRegionByPath(recorder.getSnap(),
						PathUtils.toString(targetRegion.getPath())));
		});
	}

	protected TraceMemorySpace createRegSpace(TraceThread thread) {
		try (Transaction tx = thread.getTrace().openTransaction("Create register space")) {
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
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register r0 = lang.getRegister("r0");
		Register r1 = lang.getRegister("r1");
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		//TraceThread thread = recorder.getTraceThread(mb.testThread1);
		TraceMemorySpace rs = createRegSpace(thread);
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
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register pc = lang.getRegister("pc");
		Register sp = lang.getRegister("sp");
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		TraceMemorySpace rs = createRegSpace(thread);
		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550000, 0x5555ffff), "rx");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			r -> r.isBaseRegister() && r != pc && r != sp);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		try (Transaction tx = trace.openTransaction("Add PC type")) {
			TraceCodeSpace code = trace.getCodeManager().getCodeRegisterSpace(thread, true);
			code.definedData().create(Lifespan.nowOn(0), pc, PointerDataType.dataType);
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
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register pc = lang.getRegister("pc");
		Register sp = lang.getRegister("sp");
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		TraceMemorySpace rs = createRegSpace(thread);
		mb.testProcess1.addRegion("[stack]", mb.rng(0x22220000, 0x2222ffff), "rw");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			r -> r.isBaseRegister() && r != pc && r != sp);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();
		try (Transaction tx = trace.openTransaction("Add SP type")) {
			TraceCodeSpace code = trace.getCodeManager().getCodeRegisterSpace(thread, true);
			code.definedData().create(Lifespan.nowOn(0), sp, PointerDataType.dataType);
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
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		Language lang = trace.getBaseLanguage();
		Register pc = lang.getRegister("pc");
		mb.testProcess1.addRegion("bin:.text", mb.rng(0x55550123, 0x55550321), "rx");
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		TestTargetRegisterBankInThread regs = mb.testThread1.addRegisterBank();

		//waitForCondition(() -> registerMapped(recorder, thread, pc));
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));
		try (Transaction tx = trace.openTransaction("Add PC type")) {
			TraceCodeSpace code = trace.getCodeManager().getCodeRegisterSpace(thread, true);
			code.definedData().create(Lifespan.nowOn(0), pc, PointerDataType.dataType);
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
