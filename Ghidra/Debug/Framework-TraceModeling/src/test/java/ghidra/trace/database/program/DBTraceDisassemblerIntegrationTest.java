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
import java.lang.annotation.*;
import java.util.Set;

import org.junit.*;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.google.common.collect.Range;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.language.DBTraceGuestLanguage;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DBTraceDisassemblerIntegrationTest extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceVariableSnapProgramView view;

	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	public @interface TestLanguage {
		String value();
	}

	public static class LanguageWatcher extends TestWatcher {
		String language = ProgramBuilder._TOY64_BE;

		@Override
		protected void starting(Description description) {
			language = computeLanguage(description);
		}

		private String computeLanguage(Description description) {
			TestLanguage annot = description.getAnnotation(TestLanguage.class);
			if (annot == null) {
				return ProgramBuilder._TOY64_BE;
			}
			return annot.value();
		}

		public String getLanguage() {
			return language;
		}
	}

	@Rule
	public LanguageWatcher testLanguage = new LanguageWatcher();

	@Before
	public void setUp() throws IOException {
		b = new ToyDBTraceBuilder("Testing", testLanguage.getLanguage());
		try (UndoableTransaction tid = b.startTransaction()) {
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
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceMemoryManager memoryManager = b.trace.getMemoryManager();
			memoryManager.createRegion("Region", 0, b.range(0x4000, 0x4fff),
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
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceMemorySpace space =
				b.trace.getMemoryManager().getMemorySpace(b.language.getDefaultSpace(), true);
			space.putBytes(0, b.addr(0x4000), b.buf(0x90));

			DBTraceGuestLanguage guest = b.trace.getLanguageManager().addGuestLanguage(x86);
			guest.addMappedRange(b.addr(0x4000), b.addr(guest, 0x00400000), 0x1000);

			// TODO: The more I look, the more I think I need a fully-mapped program view :(
			// As annoying as it is, I plan to do it as a wrapper, not as an extension....
			// The disassembler uses bookmarks, context, etc. for feedback. It'd be nice to
			// have that
			RegisterValue defaultContextValue =
				b.trace.getRegisterContextManager()
						.getDefaultContext(x86)
						.getDisassemblyContext(
							b.addr(guest, 0x00400000));
			InstructionSet set = new InstructionSet(x86.getAddressFactory());
			set.addBlock(dis.pseudoDisassembleBlock(
				guest.getMappedMemBuffer(0, b.addr(guest, 0x00400000)), defaultContextValue, 1));

			DBTraceCodeManager code = b.trace.getCodeManager();
			code.instructions().addInstructionSet(Range.closed(0L, 0L), set, false);

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
		try (UndoableTransaction tid =
			UndoableTransaction.start(b.getProgram(), "Disassemble (THUMB)", true)) {
			MemoryBlock text = b.createMemory(".text", "b6fa2cd0", 32, "Sample", (byte) 0);
			text.putBytes(b.addr(0xb6fa2cdc), new byte[] {
				// GDB: stmdb sp!,  {r4, r5, r6, r7, r8, lr}
				(byte) 0x2d, (byte) 0xe9, (byte) 0xf0, (byte) 0x41,
				// GDB: sub sp, #472  ; 0x1d8
				(byte) 0xf6, (byte) 0xb0 });

			AddressSet restricted = new AddressSet(b.addr(0xb6fa2cdc), b.addr(0xb6fa2ce1));
			ArmDisassembleCommand thumbDis =
				new ArmDisassembleCommand(b.addr(0xb6fa2cdc), restricted, true);
			thumbDis.applyTo(b.getProgram(), TaskMonitor.DUMMY);

			CodeUnit cu1 = b.getProgram().getListing().getCodeUnitAt(b.addr(0xb6fa2cdc));
			assertEquals("push { r4, r5, r6, r7, r8, lr  }", cu1.toString());
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
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceMemoryManager memory = b.trace.getMemoryManager();
			memory.createRegion(".text", 0, b.range(0xb6fa2cd0, 0xb6fa2cef),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			memory.putBytes(0, b.addr(0xb6fa2cdc), b.buf(
				// GDB: stmdb sp!,  {r4, r5, r6, r7, r8, lr}
				0x2d, 0xe9, 0xf0, 0x41,
				// GDB: sub sp, #472  ; 0x1d8
				0xf6, 0xb0));

			AddressSet restricted = new AddressSet(b.addr(0xb6fa2cdc), b.addr(0xb6fa2ce1));
			ArmDisassembleCommand thumbDis =
				new ArmDisassembleCommand(b.addr(0xb6fa2cdc), restricted, true);
			thumbDis.applyTo(b.trace.getFixedProgramView(0), TaskMonitor.DUMMY);

			CodeUnit cu1 = b.trace.getCodeManager().codeUnits().getAt(0, b.addr(0xb6fa2cdc));
			assertEquals("push { r4, r5, r6, r7, r8, lr  }", cu1.toString());
			CodeUnit cu2 = b.trace.getCodeManager().codeUnits().getAt(0, b.addr(0xb6fa2ce0));
			assertEquals("sub sp,#0x1d8", cu2.toString());
		}
	}
}
