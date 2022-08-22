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
package ghidra.pcode.emu.taint.trace;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.trace.AbstractTracePcodeEmulatorTest;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.taint.model.*;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public class TaintTracePcodeEmulatorTest extends AbstractTracePcodeEmulatorTest {

	public static Map.Entry<TraceAddressSnapRange, String> makeTaintEntry(Trace trace,
			Range<Long> span, AddressSpace space, long offset, String taint) {
		Address addr = space.getAddress(offset);
		return Map.entry(new ImmutableTraceAddressSnapRange(new AddressRangeImpl(addr, addr), span),
			taint);
	}

	public static Set<Map.Entry<TraceAddressSnapRange, String>> makeTaintEntries(Trace trace,
			Range<Long> span, AddressSpace space, Set<Long> offs, String taint) {
		return offs.stream()
				.map(o -> makeTaintEntry(trace, span, space, o, taint))
				.collect(Collectors.toSet());
	}

	/**
	 * Test that state is properly read from trace memory
	 * 
	 * <p>
	 * We isolate exactly a read by executing sleigh.
	 */
	@Test
	public void testReadStateMemory() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, List.of(), List.of());

			try (UndoableTransaction tid = tb.startTransaction()) {
				TracePropertyMap<String> taintMap = tb.trace.getAddressPropertyManager()
						.getOrCreatePropertyMap("Taint", String.class);
				taintMap.set(Range.atLeast(0L), tb.range(0x00400000, 0x00400003), "test_0");
			}

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.trace, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getExecutor().executeSleighLine("RAX = *0x00400000:8");

			Pair<byte[], TaintVec> valRAX =
				emuThread.getState().getVar(tb.language.getRegister("RAX"));
			TaintVec exp = TaintVec.empties(8);
			TaintSet testTaint = TaintSet.of(new TaintMark("test_0", Set.of()));
			for (int i = 0; i < 4; i++) {
				exp.set(i, testTaint);
			}
			assertEquals(exp, valRAX.getRight());
		}
	}

	@Test
	public void testReadStateRegister() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, List.of(), List.of());
			Register regRAX = tb.language.getRegister("RAX");
			Register regEBX = tb.language.getRegister("EBX");

			try (UndoableTransaction tid = tb.startTransaction()) {
				TracePropertyMap<String> taintMap = tb.trace.getAddressPropertyManager()
						.getOrCreatePropertyMap("Taint", String.class);
				TracePropertyMapRegisterSpace<String> mapSpace =
					taintMap.getPropertyMapRegisterSpace(thread, 0, true);
				mapSpace.set(Range.atLeast(0L), regEBX, "test_0");
			}

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.trace, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getExecutor().executeSleighLine("RAX = RBX");

			Pair<byte[], TaintVec> valRAX =
				emuThread.getState().getVar(regRAX);
			TaintVec exp = TaintVec.empties(8);
			TaintSet testTaint = TaintSet.of(new TaintMark("test_0", Set.of()));
			for (int i = 0; i < 4; i++) {
				exp.set(i, testTaint);
			}
			assertEquals(exp, valRAX.getRight());
		}
	}

	@Test
	public void testWriteStateMemory() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			initTrace(tb, List.of(), List.of());

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.trace, 0);
			TaintVec taintVal = TaintVec.empties(8);
			TaintSet testTaint = TaintSet.of(new TaintMark("test_0", Set.of()));
			for (int i = 0; i < 4; i++) {
				taintVal.set(i, testTaint);
			}
			emu.getSharedState()
					.setVar(tb.addr(0x00400000), 8, true,
						Pair.of(tb.arr(0, 0, 0, 0, 0, 0, 0, 0), taintVal));

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 0);
			}
			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);
			assertEquals("test_0", taintMap.get(1, tb.addr(0x00400000)));
			assertEquals("test_0", taintMap.get(1, tb.addr(0x00400003)));
			assertNull(taintMap.get(1, tb.addr(0x00400004)));
		}
	}

	@Test
	public void testWriteStateRegister() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			AddressSpace rs = tb.language.getAddressFactory().getRegisterSpace();
			TraceThread thread = initTrace(tb, List.of(), List.of());

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.trace, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			TaintVec taintVal = TaintVec.empties(8);
			TaintSet testTaint = TaintSet.of(new TaintMark("test_0", Set.of()));
			for (int i = 0; i < 4; i++) {
				taintVal.set(i, testTaint);
			}
			emuThread.getState().setVar(tb.reg("EAX"), Pair.of(tb.arr(0, 0, 0, 0), taintVal));

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 0);
			}
			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);
			TracePropertyMapRegisterSpace<String> mapSpace =
				taintMap.getPropertyMapRegisterSpace(thread, 0, false);
			// TODO: Might be nice to coalesce identical values
			//   Becomes the 2D cover optimization problem. Still could do some easy cases.
			assertEquals(
				makeTaintEntries(tb.trace, Range.atLeast(1L), rs, Set.of(0L, 1L, 2L, 3L), "test_0"),
				Set.copyOf(mapSpace.getEntries(Range.singleton(1L), tb.reg("RAX"))));
		}
	}

	@Test
	public void testEmptyTaintClears() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			AddressSpace ram = tb.language.getAddressFactory().getDefaultAddressSpace();
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;"),
				List.of(
					"MOV qword ptr [0x00600000], RAX",
					"MOV qword ptr [0x00600000], RBX"));

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.trace, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getState()
					.setVar(tb.reg("RAX"), Pair.of(
						tb.arr(0, 0, 0, 0, 0, 0, 0, 0),
						TaintVec.copies(TaintSet.parse("test_0"), 8)));

			emuThread.stepInstruction();
			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 0);
			}
			emuThread.stepInstruction();
			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 2, 0);
			}

			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);

			assertEquals(makeTaintEntries(tb.trace, Range.singleton(1L), ram, Set.of(
				0x00600000L, 0x00600001L, 0x00600002L, 0x00600003L,
				0x00600004L, 0x00600005L, 0x00600006L, 0x00600007L),
				"test_0"),
				Set.copyOf(taintMap.getEntries(
					Range.singleton(1L), tb.range(0x00600000, 0x00600007))));
		}
	}
}
