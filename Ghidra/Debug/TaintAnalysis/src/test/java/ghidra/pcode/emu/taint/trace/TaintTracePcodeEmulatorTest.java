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

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.assembler.*;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.AbstractTracePcodeEmulatorTest;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.taint.model.*;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.target.DBTraceObjectManagerTest;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;

public class TaintTracePcodeEmulatorTest extends AbstractTracePcodeEmulatorTest {

	public static Map.Entry<TraceAddressSnapRange, String> makeTaintEntry(Trace trace,
			Lifespan span, AddressSpace space, long offset, String taint) {
		Address addr = space.getAddress(offset);
		return Map.entry(new ImmutableTraceAddressSnapRange(new AddressRangeImpl(addr, addr), span),
			taint);
	}

	public static Set<Map.Entry<TraceAddressSnapRange, String>> makeTaintEntries(Trace trace,
			Lifespan span, AddressSpace space, Set<Long> offs, String taint) {
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
			TraceThread thread = initTrace(tb, "", List.of());

			try (Transaction tx = tb.startTransaction()) {
				TracePropertyMap<String> taintMap = tb.trace.getAddressPropertyManager()
						.getOrCreatePropertyMap("Taint", String.class);
				taintMap.set(Lifespan.nowOn(0), tb.range(0x00400000, 0x00400003), "test_0");
			}

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getExecutor().executeSleigh("RAX = *0x00400000:8;");

			Pair<byte[], TaintVec> valRAX =
				emuThread.getState().getVar(tb.language.getRegister("RAX"), Reason.INSPECT);
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
			TraceThread thread = initTrace(tb, "", List.of());
			Register regRAX = tb.language.getRegister("RAX");
			Register regEBX = tb.language.getRegister("EBX");

			try (Transaction tx = tb.startTransaction()) {
				TracePropertyMap<String> taintMap = tb.trace.getAddressPropertyManager()
						.getOrCreatePropertyMap("Taint", String.class);
				TracePropertyMapSpace<String> mapSpace =
					taintMap.getPropertyMapRegisterSpace(thread, 0, true);
				mapSpace.set(Lifespan.nowOn(0), regEBX, "test_0");
			}

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getExecutor().executeSleigh("RAX = RBX;");

			Pair<byte[], TaintVec> valRAX =
				emuThread.getState().getVar(regRAX, Reason.INSPECT);
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
			initTrace(tb, "", List.of());

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			TaintVec taintVal = TaintVec.empties(8);
			TaintSet testTaint = TaintSet.of(new TaintMark("test_0", Set.of()));
			for (int i = 0; i < 4; i++) {
				taintVal.set(i, testTaint);
			}
			emu.getSharedState()
					.setVar(tb.addr(0x00400000), 8, true,
						Pair.of(tb.arr(0, 0, 0, 0, 0, 0, 0, 0), taintVal));

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
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
			TraceThread thread = initTrace(tb, "", List.of());

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			TaintVec taintVal = TaintVec.empties(8);
			TaintSet testTaint = TaintSet.of(new TaintMark("test_0", Set.of()));
			for (int i = 0; i < 4; i++) {
				taintVal.set(i, testTaint);
			}
			emuThread.getState().setVar(tb.reg("EAX"), Pair.of(tb.arr(0, 0, 0, 0), taintVal));

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}
			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);
			TracePropertyMapSpace<String> mapSpace =
				taintMap.getPropertyMapRegisterSpace(thread, 0, false);
			// TODO: Might be nice to coalesce identical values
			//   Becomes the 2D cover optimization problem. Still could do some easy cases.
			assertEquals(
				makeTaintEntries(tb.trace, Lifespan.nowOn(1), rs, Set.of(0L, 1L, 2L, 3L), "test_0"),
				Set.copyOf(mapSpace.getEntries(Lifespan.at(1), tb.reg("RAX"))));
		}
	}

	@Test
	public void testEmptyTaintClears() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			AddressSpace ram = tb.language.getAddressFactory().getDefaultAddressSpace();
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					""",
				List.of(
					"MOV qword ptr [0x00600000], RAX",
					"MOV qword ptr [0x00600000], RBX"));

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getState()
					.setVar(tb.reg("RAX"), Pair.of(
						tb.arr(0, 0, 0, 0, 0, 0, 0, 0),
						TaintVec.copies(TaintSet.parse("test_0"), 8)));

			emuThread.stepInstruction();
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}
			emuThread.stepInstruction();
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 2, 0);
			}

			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);

			assertEquals(makeTaintEntries(tb.trace, Lifespan.at(1), ram, Set.of(
				0x00600000L, 0x00600001L, 0x00600002L, 0x00600003L,
				0x00600004L, 0x00600005L, 0x00600006L, 0x00600007L),
				"test_0"),
				Set.copyOf(taintMap.getEntries(
					Lifespan.at(1), tb.range(0x00600000, 0x00600007))));
		}
	}

	@Test
	public void testZeroByXor() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					""",
				List.of(
					"XOR RAX, RAX"));

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getState()
					.setVar(tb.reg("RAX"), Pair.of(
						tb.arr(1, 2, 3, 4, 5, 6, 7, 8),
						TaintVec.copies(TaintSet.parse("test_0"), 8)));
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 0, 0);
			}

			emuThread.stepInstruction();
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}

			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);
			TracePropertyMapSpace<String> mapSpace =
				taintMap.getPropertyMapRegisterSpace(thread, 0, false);

			assertEquals(Set.of(),
				Set.copyOf(mapSpace.getEntries(Lifespan.at(1), tb.reg("RAX"))));
		}
	}

	@Test
	public void testZeroByXorVia32() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					""",
				List.of(
					"XOR EAX, EAX"));

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getState()
					.setVar(tb.reg("RAX"), Pair.of(
						tb.arr(1, 2, 3, 4, 5, 6, 7, 8),
						TaintVec.copies(TaintSet.parse("test_0"), 8)));
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 0, 0);
			}

			emuThread.stepInstruction();
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}

			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);
			TracePropertyMapSpace<String> mapSpace =
				taintMap.getPropertyMapRegisterSpace(thread, 0, false);

			assertEquals(Set.of(),
				Set.copyOf(mapSpace.getEntries(Lifespan.at(1), tb.reg("RAX"))));
		}
	}

	@Test
	public void testGuestEmptyTaintClears() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "DATA:BE:64:default")) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			AddressSpace ram = tb.language.getAddressFactory().getDefaultAddressSpace();
			TraceThread thread;
			TraceGuestPlatform x64;
			try (Transaction tx = tb.startTransaction()) {
				SchemaContext ctx = XmlSchemaContext.deserialize(DBTraceObjectManagerTest.XML_CTX);
				DBTraceObjectManager objects = tb.trace.getObjectManager();
				objects.createRootObject(ctx.getSchema(new SchemaName("Session")));
				thread = tb.getOrAddThread("Targets[0].Threads[0]", 0);

				x64 = tb.trace.getPlatformManager()
						.addGuestPlatform(getSLEIGH_X86_64_LANGUAGE().getDefaultCompilerSpec());
				x64.addMappedRegisterRange();
				x64.addMappedRange(tb.addr(0x00000000), tb.addr(x64, 0x00400000), 0x10000);
				x64.addMappedRange(tb.addr(0x20000000), tb.addr(x64, 0x00600000), 0x10000);
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers"))
						.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
				// TODO: Make Sleigh work in the guest platform
				TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, 0, true);
				regs.setValue(x64, 0,
					new RegisterValue(tb.reg(x64, "RIP"), BigInteger.valueOf(0x00400000)));

				Assembler asm = Assemblers.getAssembler(x64.getLanguage());
				AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(x64, 0x00400000));
				buf.assemble("MOV qword ptr [0x00600000], RAX");
				buf.assemble("MOV qword ptr [0x00600000], RBX");
				mm.putBytes(0, tb.addr(0x00000000), ByteBuffer.wrap(buf.getBytes()));
			}

			TaintTracePcodeEmulator emu = new TaintTracePcodeEmulator(x64, 0);
			PcodeThread<Pair<byte[], TaintVec>> emuThread = emu.newThread(thread.getPath());
			emuThread.getState()
					.setVar(tb.reg(x64, "RAX"), Pair.of(
						tb.arr(0, 0, 0, 0, 0, 0, 0, 0),
						TaintVec.copies(TaintSet.parse("test_0"), 8)));

			emuThread.stepInstruction();
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(x64, 1, 0);
			}
			emuThread.stepInstruction();
			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(x64, 2, 0);
			}

			TracePropertyMap<String> taintMap =
				tb.trace.getAddressPropertyManager().getPropertyMap("Taint", String.class);

			assertEquals(makeTaintEntries(tb.trace, Lifespan.at(1), ram, Set.of(
				0x20000000L, 0x20000001L, 0x20000002L, 0x20000003L,
				0x20000004L, 0x20000005L, 0x20000006L, 0x20000007L),
				"test_0"),
				Set.copyOf(taintMap.getEntries(
					Lifespan.at(1), tb.range(0x20000000, 0x20000007))));
		}
	}
}
