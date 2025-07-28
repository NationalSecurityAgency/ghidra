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
package ghidra.trace.database.program;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.junit.*;

import db.Transaction;
import ghidra.app.cmd.disassemble.*;
import ghidra.app.plugin.assembler.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.guest.DBTraceGuestPlatform;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.*;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.util.LanguageTestWatcher;
import ghidra.trace.util.LanguageTestWatcher.TestLanguage;
import ghidra.util.exception.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DBTraceDisassemblerIntegrationTest extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceVariableSnapProgramView view;

	@Rule
	public LanguageTestWatcher testLanguage = new LanguageTestWatcher();

	@Before
	public void setUp() throws Exception {
		b = new ToyDBTraceBuilder("Testing", testLanguage.getLanguage());

		try (Transaction tx = b.startTransaction()) {
			b.createRootObject("Target");
			b.trace.getTimeManager().createSnapshot("Initialize");
		}

		view = b.trace.getProgramView();
	}

	@After
	public void tearDown() {
		b.close();
	}

	@Test
	public void testSingleInstruction() throws IOException, CancelledException, VersionException,
			DuplicateNameException, TraceOverlappedRegionException {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memoryManager = b.trace.getMemoryManager();
			memoryManager.createRegion("Memory[Region]", 0, b.range(0x4000, 0x4fff),
				TraceMemoryFlag.EXECUTE, TraceMemoryFlag.READ);
			// NOTE: Disassembler gathers initialized ranges at construction.
			Disassembler dis = Disassembler.getDisassembler(view, true, true, false,
				new ConsoleTaskMonitor(), msg -> System.out.println("Listener: " + msg));
			DBTraceMemorySpace space =
				memoryManager.getMemorySpace(b.language.getDefaultSpace(), true);
			space.putBytes(0, b.addr(0x4000), b.buf(0xf4, 0x00));
			dis.disassemble(b.addr(0x4000), b.set(b.range(0x4000, 0x4001)), true);
		}

		DBTraceCodeManager code = b.trace.getCodeManager();
		DBTraceCodeUnitAdapter cu = code.codeUnits().getAt(0, b.addr(0x4000));
		// NOTE: This assert fails on occasion, when running all project's tests, and IDK why...
		assertEquals("ret", cu.getMnemonicString());

		File saved = b.save();
		try (ToyDBTraceBuilder r = new ToyDBTraceBuilder(saved)) {
			DBTraceCodeUnitAdapter restoredCu =
				r.trace.getCodeManager().codeUnits().getAt(0, r.addr(0x4000));
			assertEquals("ret", restoredCu.getMnemonicString());
		}
	}

	@Test
	public void testSingleGuestInstruction() throws AddressOverflowException {
		Language x86 = getSLEIGH_X86_LANGUAGE();
		Disassembler dis = Disassembler.getDisassembler(x86, x86.getAddressFactory(),
			new ConsoleTaskMonitor(), msg -> System.out.println("Listener: " + msg));
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemorySpace space =
				b.trace.getMemoryManager().getMemorySpace(b.language.getDefaultSpace(), true);
			space.putBytes(0, b.addr(0x4000), b.buf(0x90));

			DBTraceGuestPlatform guest =
				b.trace.getPlatformManager().addGuestPlatform(x86.getDefaultCompilerSpec());
			guest.addMappedRange(b.addr(0x4000), b.addr(guest, 0x00400000), 0x1000);

			/*
			 * TODO: The more I look, the more I think I need a fully-mapped program view :( As
			 * annoying as it is, I plan to do it as a wrapper, not as an extension.... The
			 * disassembler uses bookmarks, context, etc. for feedback. It'd be nice to have that.
			 */
			RegisterValue defaultContextValue =
				b.trace.getRegisterContextManager()
						.getDefaultContext(x86)
						.getDisassemblyContext(
							b.addr(guest, 0x00400000));
			InstructionSet set = new InstructionSet(x86.getAddressFactory());
			set.addBlock(dis.pseudoDisassembleBlock(
				guest.getMappedMemBuffer(0, b.addr(guest, 0x00400000)), defaultContextValue, 1));

			DBTraceCodeManager code = b.trace.getCodeManager();
			code.instructions().addInstructionSet(Lifespan.at(0), guest, set, false);

			DBTraceInstruction ins = code.instructions().getAt(0, b.addr(0x4000));
			// TODO: This is great, but probably incomplete.
			// Anything asking for fall-through or address operands is liable to have problems
			assertEquals("NOP", ins.getMnemonicString());
			assertEquals(b.addr(guest, 0x00400001), ins.getGuestDefaultFallThrough());
			assertEquals(b.addr(0x4001), ins.getDefaultFallThrough());
		}
	}

	@Test
	public void testThumbSampleProgramDB() throws Exception {
		ProgramBuilder b = new ProgramBuilder(getName(), ProgramBuilder._ARM);
		try (Transaction tx = b.getProgram().openTransaction("Disassemble (THUMB)")) {
			MemoryBlock text = b.createMemory("Memory[.text]", "b6fa2cd0", 32, "Sample", (byte) 0);
			text.putBytes(b.addr(0xb6fa2cdc), new byte[] {
				// GDB: stmdb sp!,  {r4,r5,r6,r7,r8,lr}
				(byte) 0x2d, (byte) 0xe9, (byte) 0xf0, (byte) 0x41,
				// GDB: sub sp, #472  ; 0x1d8
				(byte) 0xf6, (byte) 0xb0 });

			AddressSet restricted = new AddressSet(b.addr(0xb6fa2cdc), b.addr(0xb6fa2ce1));
			ArmDisassembleCommand thumbDis =
				new ArmDisassembleCommand(b.addr(0xb6fa2cdc), restricted, true);
			thumbDis.applyTo(b.getProgram(), TaskMonitor.DUMMY);

			CodeUnit cu1 = b.getProgram().getListing().getCodeUnitAt(b.addr(0xb6fa2cdc));
			assertEquals("push {r4,r5,r6,r7,r8,lr}", cu1.toString());
			CodeUnit cu2 = b.getProgram().getListing().getCodeUnitAt(b.addr(0xb6fa2ce0));
			assertEquals("sub sp,#0x1d8", cu2.toString());
		}
		finally {
			b.dispose();
		}
	}

	@Test
	@TestLanguage(ProgramBuilder._ARM)
	public void testThumbSampleDBTrace() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			memory.createRegion("Memory[.text]", 0, b.range(0xb6fa2cd0, 0xb6fa2cef),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			memory.putBytes(0, b.addr(0xb6fa2cdc), b.buf(
				// GDB: stmdb sp!,  {r4,r5,r6,r7,r8,lr}
				0x2d, 0xe9, 0xf0, 0x41,
				// GDB: sub sp, #472  ; 0x1d8
				0xf6, 0xb0));

			AddressSet restricted = new AddressSet(b.addr(0xb6fa2cdc), b.addr(0xb6fa2ce1));
			ArmDisassembleCommand thumbDis =
				new ArmDisassembleCommand(b.addr(0xb6fa2cdc), restricted, true);
			thumbDis.applyTo(b.trace.getFixedProgramView(0), TaskMonitor.DUMMY);

			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0xb6fa2cdc));
			assertEquals("push {r4,r5,r6,r7,r8,lr}", cu1.toString());
			CodeUnit cu2 = cuManager.getAt(0, b.addr(0xb6fa2ce0));
			assertEquals("sub sp,#0x1d8", cu2.toString());
		}
	}

	@Test
	@TestLanguage("MIPS:BE:64:default")
	public void testDelaySlotSampleDBTrace() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			memory.createRegion("Memory[.text]", 0, b.range(0x120000000L, 0x120010000L),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			memory.putBytes(0, b.addr(0x1200035b4L), b.buf(
				// bal LAB_1200035bc
				0x04, 0x11, 0x00, 0x01,
				// _nop
				0x00, 0x00, 0x00, 0x00));

			AddressSet restricted = new AddressSet(b.addr(0x1200035b4L), b.addr(0x1200035bbL));
			MipsDisassembleCommand mipsDis =
				new MipsDisassembleCommand(b.addr(0x1200035b4L), restricted, false);
			mipsDis.applyTo(b.trace.getFixedProgramView(0), TaskMonitor.DUMMY);

			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0x1200035b4L));
			assertEquals("bal 0x1200035bc", cu1.toString());
			CodeUnit cu2 = cuManager.getAt(0, b.addr(0x1200035b8L));
			assertEquals("_nop", cu2.toString());
		}
	}

	@Test
	@TestLanguage(ProgramBuilder._X64)
	public void test64BitX86DBTrace() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			memory.createRegion("Memory[.text]", 0, b.range(0x00400000, 0x00400fff));
			memory.putBytes(0, b.addr(0x00400000), b.buf(
				// MOV RCX,RAX; Same encoding as DEC EAX; MOV ECX,EAX outside long mode
				0x48, 0x89, 0xc1));

			AddressSet restricted = new AddressSet(b.addr(0x00400000), b.addr(0x00400002));
			X86_64DisassembleCommand x86Dis =
				new X86_64DisassembleCommand(b.addr(0x00400000), restricted, false);
			x86Dis.applyTo(b.trace.getFixedProgramView(0), TaskMonitor.DUMMY);

			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0x00400000));
			assertEquals("MOV RCX,RAX", cu1.toString());
		}

		File saved = b.save();

		// Check that required context is actually saved and restored
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder(saved)) {
			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0x00400000));
			assertEquals("MOV RCX,RAX", cu1.toString());
		}
	}

	@Test
	@TestLanguage(ProgramBuilder._X64)
	public void test32BitX64CompatDBTrace() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			memory.createRegion("Memory[.text]", 0, b.range(0x00400000, 0x00400fff));
			memory.putBytes(0, b.addr(0x00400000), b.buf(
				// DEC EAX; but REX.W if context not heeded
				0x48,
				// MOV ECX,EAX
				0x89, 0xc1));

			AddressSet restricted = new AddressSet(b.addr(0x00400000), b.addr(0x00400002));
			X86_64DisassembleCommand x86Dis =
				new X86_64DisassembleCommand(b.addr(0x00400000), restricted, true);
			x86Dis.applyTo(b.trace.getFixedProgramView(0), TaskMonitor.DUMMY);

			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0x00400000));
			assertEquals("DEC EAX", cu1.toString());
			CodeUnit cu2 = cuManager.getAt(0, b.addr(0x00400001));
			assertEquals("MOV ECX,EAX", cu2.toString());
		}

		File saved = b.save();

		// Check that required context is actually saved and restored
		try (ToyDBTraceBuilder b = new ToyDBTraceBuilder(saved)) {
			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0x00400000));
			assertEquals("DEC EAX", cu1.toString());
			CodeUnit cu2 = cuManager.getAt(0, b.addr(0x00400001));
			assertEquals("MOV ECX,EAX", cu2.toString());
		}
	}

	@Test
	@TestLanguage(ProgramBuilder._X86)
	public void test32BitX86DBTrace() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			memory.createRegion("Memory[.text]", 0, b.range(0x00400000, 0x00400fff));
			memory.putBytes(0, b.addr(0x00400000), b.buf(
				// DEC EAX
				0x48,
				// MOV ECX,EAX
				0x89, 0xc1));

			AddressSet restricted = new AddressSet(b.addr(0x00400000), b.addr(0x00400002));
			DisassembleCommand dis =
				new DisassembleCommand(b.addr(0x00400000), restricted, true);
			dis.applyTo(b.trace.getFixedProgramView(0), TaskMonitor.DUMMY);

			DBTraceCodeUnitsMemoryView cuManager = b.trace.getCodeManager().codeUnits();
			CodeUnit cu1 = cuManager.getAt(0, b.addr(0x00400000));
			assertEquals("DEC EAX", cu1.toString());
			CodeUnit cu2 = cuManager.getAt(0, b.addr(0x00400001));
			assertEquals("MOV ECX,EAX", cu2.toString());
		}
	}

	record Repetition(Lifespan lifespan, boolean overwrite) {}

	protected <T> List<T> toList(Iterable<? extends T> it) {
		return StreamSupport.stream(it.spliterator(), false).collect(Collectors.toList());
	}

	protected void runTestCoalesceInstructions(List<Repetition> repetitions) throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			DBTraceCodeManager code = b.trace.getCodeManager();

			memory.createRegion("Memory[.text]", 0, b.range(0x00400000, 0x00400fff));
			Assembler asm = Assemblers.getAssembler(b.language);
			Address entry = b.addr(0x00400000);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);
			buf.assemble("imm r0, #123");
			buf.assemble("mov r1, r0");
			buf.assemble("ret");

			long snap = Lifespan.isScratch(repetitions.get(0).lifespan.lmin()) ? Long.MIN_VALUE : 0;
			memory.putBytes(snap, entry, ByteBuffer.wrap(buf.getBytes()));

			AddressFactory factory = b.trace.getBaseAddressFactory();
			Disassembler dis =
				Disassembler.getDisassembler(b.language, factory, TaskMonitor.DUMMY, null);
			InstructionSet set = new InstructionSet(factory);
			set.addBlock(dis.pseudoDisassembleBlock(memory.getBufferAt(snap, entry), null, 10));

			List<TraceCodeUnit> units = null;
			TraceAddressSnapRange all =
				new ImmutableTraceAddressSnapRange(b.range(0, -1), Lifespan.ALL);
			for (Repetition rep : repetitions) {
				code.instructions().addInstructionSet(rep.lifespan, set, rep.overwrite);
				if (units == null) {
					units = toList(code.definedUnits().getIntersecting(all));
				}
				else {
					/**
					 * Technically, getIntersecting makes no guarantee regarding order.
					 * Nevertheless, the structure shouldn't be perturbed, so I think it's fair to
					 * expect the same order.
					 */
					assertEquals(units, toList(code.definedUnits().getIntersecting(all)));
				}
			}
		}
	}

	@Test
	@TestLanguage(ProgramBuilder._TOY64_BE)
	public void testCoalesceInstructionsMinTwiceNoOverwrite() throws Exception {
		runTestCoalesceInstructions(List.of(
			new Repetition(Lifespan.nowOn(Long.MIN_VALUE), false),
			new Repetition(Lifespan.nowOn(Long.MIN_VALUE), false)));
	}

	@Test
	@TestLanguage(ProgramBuilder._TOY64_BE)
	public void testCoalesceInstructionsMinTwiceYesOverwrite() throws Exception {
		runTestCoalesceInstructions(List.of(
			new Repetition(Lifespan.nowOn(Long.MIN_VALUE), true),
			new Repetition(Lifespan.nowOn(Long.MIN_VALUE), true)));
	}

	@Test
	@TestLanguage(ProgramBuilder._TOY64_BE)
	public void testCoalesceInstructionsZeroTwiceYesOverwrite() throws Exception {
		runTestCoalesceInstructions(List.of(
			new Repetition(Lifespan.nowOn(0), true),
			new Repetition(Lifespan.nowOn(0), true)));
	}

	@Test
	@TestLanguage(ProgramBuilder._TOY64_BE)
	public void testCoalesceInstructionsZeroThenOneYesOverwrite() throws Exception {
		runTestCoalesceInstructions(List.of(
			new Repetition(Lifespan.nowOn(0), true),
			new Repetition(Lifespan.nowOn(1), true)));
	}

	@Test
	@TestLanguage(ProgramBuilder._TOY64_BE)
	public void testCoalesceInstructionsZeroOnlyThenOneNoOverwrite() throws Exception {
		runTestCoalesceInstructions(List.of(
			new Repetition(Lifespan.at(0), false),
			new Repetition(Lifespan.nowOn(1), false)));
	}

	@Test
	@TestLanguage(ProgramBuilder._TOY64_BE)
	public void testCoalesceInstructionsZeroOnlyThenOneYesOverwrite() throws Exception {
		runTestCoalesceInstructions(List.of(
			new Repetition(Lifespan.at(0), true),
			new Repetition(Lifespan.nowOn(1), true)));
	}

	@Test
	public void testNoCoalesceAcrossByteChanges() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			DBTraceCodeManager code = b.trace.getCodeManager();

			memory.createRegion("Memory[.text]", 0, b.range(0x00400000, 0x00400fff));
			Assembler asm = Assemblers.getAssembler(b.language);
			Address entry = b.addr(0x00400000);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);
			buf.assemble("imm r0, #123");
			buf.assemble("mov r1, r0");
			buf.assemble("ret");

			memory.putBytes(-1, entry, ByteBuffer.wrap(buf.getBytes()));

			AddressFactory factory = b.trace.getBaseAddressFactory();
			Disassembler dis =
				Disassembler.getDisassembler(b.language, factory, TaskMonitor.DUMMY, null);
			InstructionSet set = new InstructionSet(factory);
			set.addBlock(dis.pseudoDisassembleBlock(memory.getBufferAt(-1, entry), null, 10));

			TraceAddressSnapRange all =
				new ImmutableTraceAddressSnapRange(b.range(0, -1), Lifespan.ALL);
			code.instructions().addInstructionSet(Lifespan.nowOn(-1), set, true);
			/**
			 * This is already a bogus sort of operation: The prototypes may not match the bytes. In
			 * any case, we should not expect coalescing.
			 */
			code.instructions().addInstructionSet(Lifespan.nowOn(0), set, true);
			List<TraceCodeUnit> units = toList(code.definedUnits().getIntersecting(all));
			assertEquals(6, units.size());
		}
	}
}
