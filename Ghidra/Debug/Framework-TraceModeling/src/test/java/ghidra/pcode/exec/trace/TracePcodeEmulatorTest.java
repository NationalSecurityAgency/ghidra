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
package ghidra.pcode.exec.trace;

import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.database.UndoableTransaction;

public class TracePcodeEmulatorTest extends AbstractGhidraHeadlessIntegrationTest {

	/**
	 * Build a trace with a program ready for emulation
	 * 
	 * <p>
	 * This creates a relatively bare-bones trace with initial state for testing trace
	 * emulation/interpolation. It adds ".text" and "stack" regions, creates a thread, assembles
	 * given instructions, and then executes the given SLEIGH source (in the context of the new
	 * thread) to finish initializing the trace. Note, though given first, the SLEIGH is executed
	 * after assembly. Thus, it can be used to modify the resulting machine code by modifying the
	 * memory where it was assembled.
	 * 
	 * @param tb the trace builder
	 * @param stateInit SLEIGH source lines to execute to initialize the trace state before
	 *            emulation. Each line must end with ";"
	 * @param assembly lines of assembly to place starting at {@code 0x00400000}
	 * @return a new trace thread, whose register state is initialized as specified
	 * @throws Throwable if anything goes wrong
	 */
	public TraceThread initTrace(ToyDBTraceBuilder tb, List<String> stateInit,
			List<String> assembly) throws Throwable {
		TraceMemoryManager mm = tb.trace.getMemoryManager();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread1", 0);
			mm.addRegion("Regions[bin:.text]",
				Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			mm.addRegion("Regions[stack1]",
				Range.atLeast(0L), tb.range(0x00100000, 0x0010ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			Iterator<Instruction> block = assembly.isEmpty() ? Collections.emptyIterator()
					: asm.assemble(tb.addr(0x00400000), assembly.toArray(String[]::new));
			Instruction last = null;
			while (block.hasNext()) {
				last = block.next();
			}
			Msg.info(this, "Assembly ended at: " + last.getMaxAddress());
			PcodeExecutor<byte[]> exec =
				TraceSleighUtils.buildByteExecutor(tb.trace, 0, thread, 0);
			PcodeProgram initProg = SleighProgramCompiler.compileProgram(
				(SleighLanguage) tb.language, "test", stateInit,
				SleighUseropLibrary.nil());
			exec.execute(initProg, SleighUseropLibrary.nil());
		}
		return thread;
	}

	/**
	 * Test a single instruction
	 * 
	 * <p>
	 * This tests that the internal p-code execution is working, that intermediate writes do not
	 * affect the trace, and that the write-down method works. That written state is also verified
	 * against the expected instruction behavior.
	 */
	@Test
	public void testSinglePUSH() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;"),
				List.of(
					"PUSH 0xdeadbeef"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();

			// Verify no changes to trace
			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("RSP", tb.trace, 0, thread, 0));
			assertEquals(BigInteger.valueOf(0),
				TraceSleighUtils.evaluate("*:4 0x0010fffc:8", tb.trace, 0, thread, 0));

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, true);
			}

			// 4, not 8 bytes pushed?
			assertEquals(BigInteger.valueOf(0x0010fffc),
				TraceSleighUtils.evaluate("RSP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xdeadbeefL),
				TraceSleighUtils.evaluate("*:4 RSP", tb.trace, 1, thread, 0));

			assertEquals(tb.addr(0x00400006),
				tb.trace.getStackManager()
						.getStack(thread, 1, false)
						.getFrame(0, false)
						.getProgramCounter());
		}
	}

	/**
	 * Test two consecutive instructions
	 * 
	 * <p>
	 * This tests both the fall-through case, and that the emulator is using the cached intermediate
	 * register state, rather than reading through to the trace, again.
	 */
	@Test
	public void testDoublePUSH() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;"),
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x0010fff8),
				TraceSleighUtils.evaluate("RSP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xdeadbeefL),
				TraceSleighUtils.evaluate("*:4 (RSP + 4)", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xbaadf00dL),
				TraceSleighUtils.evaluate("*:4 RSP", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test the branch case
	 * 
	 * <p>
	 * This tests that branch instructions function. Both the emulator's counter and the PC of the
	 * machine state are verified after the JMP.
	 */
	@Test
	public void testJMP() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			Register pc = tb.language.getProgramCounter();

			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"RAX = 0x12345678;"),
				List.of(
					"JMP 0x00400007",       // 2 bytes
					"MOV EAX,0xdeadbeef",   // 5 bytes
					"MOV ECX,0xbaadf00d")); // 5 bytes

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00400007), emuThread.getCounter());
			assertArrayEquals(tb.arr(0x07, 0, 0x40, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(pc));

			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("RSP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x0040000c),
				TraceSleighUtils.evaluate("RIP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x12345678),
				TraceSleighUtils.evaluate("RAX", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xbaadf00dL),
				TraceSleighUtils.evaluate("RCX", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test branch with flow
	 * 
	 * <p>
	 * This will test both context flow and some language-specific state modifiers, since ARM needs
	 * to truncate the last bit when jumping into THUMB mode.
	 */
	@Test
	public void testBX() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "ARM:LE:32:v8")) {
			Register pc = tb.language.getProgramCounter();
			Register ctxreg = tb.language.getContextBaseRegister();
			Register tmode = tb.language.getRegister("TMode");

			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			RegisterValue thumbCtx =
				new RegisterValue(ctxreg, BigInteger.ZERO).assign(tmode, BigInteger.ONE);
			AssemblyPatternBlock thumbPat = AssemblyPatternBlock.fromRegisterValue(thumbCtx);

			// NOTE: Assemble the thumb section separately
			TraceThread thread = initTrace(tb,
				List.of(
					"pc = 0x00400000;",
					"sp = 0x00110000;",
					"*:4 0x00400008:4 = 0x00401001;"), // immediately after bx
				List.of(
					"ldr r6, [pc,#0]!", // 4 bytes,   pc+4 should be 00400008
					"bx r6"));          // 4 bytes

			byte[] mov = asm.assembleLine(tb.addr(0x00401000),
				"movs r0, #123", thumbPat); // #123 is decimal
			try (UndoableTransaction tid = tb.startTransaction()) {
				asm.patchProgram(mov, tb.addr(0x00401000));
			}

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00401000), emuThread.getCounter());
			assertArrayEquals(tb.arr(0, 0x10, 0x40, 0),
				emuThread.getState().getVar(pc));
			assertEquals(new RegisterValue(ctxreg, BigInteger.valueOf(0x8000_0000_0000_0000L)),
				emuThread.getContext());
			assertArrayEquals(tb.arr(0, 0, 0, 0, 0, 0, 0, 0x80),
				emuThread.getState().getVar(ctxreg));

			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("sp", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x00401002),
				TraceSleighUtils.evaluate("pc", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(123),
				TraceSleighUtils.evaluate("r0", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * This tests a language without a real contextreg
	 */
	@Test
	public void testIMM() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "Toy:BE:64:default")) {
			assertEquals(Register.NO_CONTEXT, tb.language.getContextBaseRegister());

			TraceThread thread = initTrace(tb,
				List.of(
					"pc = 0x00400000;",
					"sp = 0x00110000;"),
				List.of(
					"imm r0, #1234")); // decimal

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("sp", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x00400002),
				TraceSleighUtils.evaluate("pc", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(1234),
				TraceSleighUtils.evaluate("r0", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * This tests the delay-slot semantics of the emulator
	 */
	@Test
	public void testBRDS() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "Toy:BE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"pc = 0x00400000;",
					"sp = 0x00110000;"),
				List.of(
					"brds 0x00400006",
					"imm r0, #1234", // decimal
					"imm r0, #2020",
					"imm r1, #2021"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction(); // brds and 1st imm executed
			emuThread.stepInstruction(); // 3rd imm executed

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x00400008),
				TraceSleighUtils.evaluate("pc", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(1234),
				TraceSleighUtils.evaluate("r0", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(2021),
				TraceSleighUtils.evaluate("r1", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test the instruction decoder considers the cached state
	 * 
	 * <p>
	 * This may not reflect the semantics of an actual processor in these situations, since they may
	 * have instruction caching. Emulating such semantics is TODO, if at all. NB. This also tests
	 * that PC-relative addressing works, since internally the emulator advances the counter after
	 * execution of each instruction. Addressing is computed by the SLEIGH instruction parser and
	 * encoded as a constant deref in the p-code.
	 */
	@Test
	public void testSelfModifyingX86() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"RAX = 0x12345678;",
					// NB. Assembly actually happens first, so this is modifying
					"*:1 0x00400007:8 = *0x00400007:8 ^ 0xcc;"),
				List.of(
					// First instruction undoes the modification above
					"XOR byte ptr [0x00400007], 0xcc", // 7 bytes
					"MOV EAX,0xdeadbeef"));            // 5 bytes

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();

			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("RSP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x0040000c),
				TraceSleighUtils.evaluate("RIP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xdeadbeefL),
				TraceSleighUtils.evaluate("RAX", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test a two-instruction sample with p-code stepping
	 * 
	 * <p>
	 * Two instructions are used here to ensure that stepping will proceed to the next instruction.
	 * This will also serve as an evaluation of the API.
	 */
	@Test
	public void testDoublePUSH_pCode() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;"),
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			assertNull(emuThread.getFrame());

			emuThread.stepPcodeOp();
			for (int i = 0; !emuThread.getFrame().isFinished(); i++) {
				assertEquals(i, emuThread.getFrame().index());
				emuThread.stepPcodeOp();
			}
			assertTrue(emuThread.getFrame().isFallThrough());
			assertEquals(tb.addr(0x00400000), emuThread.getCounter());

			emuThread.stepPcodeOp();
			assertNull(emuThread.getFrame());
			assertEquals(tb.addr(0x00400006), emuThread.getCounter());

			emuThread.stepPcodeOp();
			assertEquals(0, emuThread.getFrame().index());

			emuThread.finishInstruction();
			assertNull(emuThread.getFrame());

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x0040000c),
				TraceSleighUtils.evaluate("RIP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x0010fff8),
				TraceSleighUtils.evaluate("RSP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xdeadbeefL),
				TraceSleighUtils.evaluate("*:4 (RSP + 4)", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xbaadf00dL),
				TraceSleighUtils.evaluate("*:4 RSP", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test the inject method
	 * 
	 * <p>
	 * This tests that injects work, and that they can invoke a userop from a client-provided
	 * library
	 */
	@Test
	public void testInject() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			final StringBuilder dumped = new StringBuilder();
			SleighUseropLibrary<byte[]> library = new AnnotatedSleighUseropLibrary<byte[]>() {
				@Override
				protected Lookup getMethodLookup() {
					return MethodHandles.lookup();
				}

				@SleighUserop
				public void hexdump(byte[] in) {
					dumped.append(NumericUtilities.convertBytesToString(in));
				}
			};
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;"),
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0, library);
			emu.inject(tb.addr(0x00400006), List.of("hexdump(RSP);"));
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();

			emuThread.stepInstruction();
			assertEquals("", dumped.toString());

			emuThread.stepInstruction();
			assertEquals("fcff100000000000", dumped.toString()); // LE
		}
	}

	/**
	 * Test that injects and interrupts work
	 * 
	 * <p>
	 * We'll put the interrupt within a more involved inject, so we can single-step the remainder of
	 * the inject, too. This will check the semantics of stepping over the interrupt.
	 */
	@Test
	public void testInjectedInterrupt() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			final StringBuilder dumped = new StringBuilder();
			SleighUseropLibrary<byte[]> library = new AnnotatedSleighUseropLibrary<byte[]>() {
				@Override
				protected Lookup getMethodLookup() {
					return MethodHandles.lookup();
				}

				@SleighUserop
				public void hexdump(byte[] in) {
					dumped.append(NumericUtilities.convertBytesToString(in));
				}
			};
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;"),
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0, library);
			emu.inject(tb.addr(0x00400006), List.of(
				"hexdump(RSP);",
				"emu_swi();",
				"hexdump(RIP);",
				"emu_exec_decoded();",
				"hexdump(RIP);"));
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();

			try {
				emuThread.run();
			}
			catch (InterruptPcodeExecutionException e) {
				assertEquals(e.getFrame(), emuThread.getFrame());
			}
			assertEquals("fcff100000000000", dumped.toString()); // LE
			dumped.delete(0, dumped.length());

			emuThread.stepPcodeOp();
			assertEquals("0600400000000000", dumped.toString());
			dumped.delete(0, dumped.length());

			emuThread.finishInstruction();
			assertEquals("0c00400000000000", dumped.toString());
			dumped.delete(0, dumped.length());

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0xbaadf00dL),
				TraceSleighUtils.evaluate("*:4 RSP", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test that conditional breakpoints work
	 */
	@Test
	public void testBreakpoints() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"RAX = 0;"),
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			emu.addBreakpoint(tb.addr(0x00400000), "RAX == 1");
			emu.addBreakpoint(tb.addr(0x00400006), "RAX == 0");
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();

			try {
				emuThread.run();
			}
			catch (InterruptPcodeExecutionException e) {
				assertEquals(e.getFrame(), emuThread.getFrame());
			}
			assertEquals(tb.addr(0x00400006), emuThread.getCounter());
		}
	}

	/**
	 * Test ARM's CLZ instruction
	 * 
	 * <p>
	 * This tests that the state modifiers are properly invoked on CALLOTHER.
	 */
	@Test
	public void testCLZ() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "ARM:LE:32:v8")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"pc = 0x00400000;",
					"sp = 0x00110000;",
					"r0 = 0x00008000;"),
				List.of(
					"clz r1, r0"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(16),
				TraceSleighUtils.evaluate("r1", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test x86's MOVAPS instruction
	 * 
	 * <p>
	 * This test hits a SUBPIECE instruction where the two input operands have differing sizes.
	 */
	@Test
	public void testMOVAPS() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			Register pc = tb.language.getProgramCounter();

			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"*:8 0x00600008:8 = 0x0123456789abcdef;", // LE
					"*:8 0x00600000:8 = 0xfedcba9876543210;"),
				List.of(
					"MOVAPS XMM0, xmmword ptr [0x00600000]"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00400007), emuThread.getCounter());
			assertArrayEquals(tb.arr(0x07, 0, 0x40, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(pc));

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(new BigInteger("0123456789abcdeffedcba9876543210", 16),
				TraceSleighUtils.evaluate("XMM0", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test x86's SAR instruction
	 * 
	 * <p>
	 * This test hits an INT_SRIGHT p-code op where the two input operands have differing sizes.
	 */
	@Test
	public void testSAR() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			Register pc = tb.language.getProgramCounter();

			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"RAX = 0x7fffffff;",
					"RCX = 4;"),
				List.of(
					"SAR EAX, CL"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00400002), emuThread.getCounter());
			assertArrayEquals(tb.arr(0x02, 0, 0x40, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(pc));

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x7ffffff),
				TraceSleighUtils.evaluate("RAX", tb.trace, 1, thread, 0));
		}
	}

	@Test
	public void testCachedReadAfterSmallWrite() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"RAX = 0x12345678;"),
				List.of(
					"XOR AH, AH",
					"MOV RCX, RAX"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x12340078),
				TraceSleighUtils.evaluate("RAX", tb.trace, 1, thread, 0));
		}
	}

	@Test(expected = AccessPcodeExecutionException.class)
	public void testCheckedMOV_err() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;"),
				List.of(
					"MOV RCX,RAX"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0) {
				@Override
				protected PcodeExecutorState<byte[]> newState(TraceThread thread) {
					return new RequireIsKnownTraceCachedWriteBytesPcodeExecutorState(trace, snap,
						thread, 0);
				}
			};
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
		}
	}

	@Test
	public void testCheckedMOV_known() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RAX = 0x1234;"), // Make it known in the trace
				List.of(
					"MOV RCX,RAX"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0) {
				@Override
				protected PcodeExecutorState<byte[]> newState(TraceThread thread) {
					return new RequireIsKnownTraceCachedWriteBytesPcodeExecutorState(trace, snap,
						thread, 0);
				}
			};
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			// No assertions. It should simply not throw an exception.
		}
	}

	@Test(expected = AccessPcodeExecutionException.class)
	public void testCheckedMOV_knownPast_err() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RAX = 0x1234;"), // Make it known in the trace
				List.of(
					"MOV RCX,RAX"));

			// Start emulator one snap later
			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 1) {
				@Override
				protected PcodeExecutorState<byte[]> newState(TraceThread thread) {
					return new RequireIsKnownTraceCachedWriteBytesPcodeExecutorState(trace, snap,
						thread, 0);
				}
			};
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			// No assertions. It should throw an exception.
		}
	}

	@Test
	public void testCheckedMOV_knownPast_has() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RAX = 0x1234;"), // Make it known in the trace
				List.of(
					"MOV RCX,RAX"));

			// Start emulator one snap later, but with "has-known" checks
			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 1) {
				@Override
				protected PcodeExecutorState<byte[]> newState(TraceThread thread) {
					return new RequireHasKnownTraceCachedWriteBytesPcodeExecutorState(trace, snap,
						thread, 0);
				}
			};
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			// No assertions. It should simply not throw an exception.
		}
	}

	@Test
	public void testCheckedMOV_initialized() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;"),
				List.of(
					"MOV RAX,0", // Have the program initialize it
					"MOV RCX,RAX"));

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0) {
				@Override
				protected PcodeExecutorState<byte[]> newState(TraceThread thread) {
					return new RequireIsKnownTraceCachedWriteBytesPcodeExecutorState(trace, snap,
						thread, 0);
				}
			};
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContextWithDefault();
			emuThread.stepInstruction();
			emuThread.stepInstruction();
			// No assertions. It should simply not throw an exception.
		}
	}

	@Test
	public void testDEC_MOV_compat32() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			Language lang = tb.trace.getBaseLanguage();
			Register ctxReg = lang.getContextBaseRegister();
			Register opsizeReg = lang.getRegister("opsize");
			Register addrsizeReg = lang.getRegister("addrsize");
			Register longModeReg = lang.getRegister("longMode");
			RegisterValue ctxVal = new RegisterValue(ctxReg)
					.assign(opsizeReg, BigInteger.ONE)
					.assign(addrsizeReg, BigInteger.ONE)
					.assign(longModeReg, BigInteger.ZERO);
			try (UndoableTransaction tid = tb.startTransaction()) {
				tb.trace.getRegisterContextManager()
						.setValue(lang, ctxVal, Range.atLeast(0L),
							tb.range(0x00400000, 0x00400002));
			}
			TraceThread thread = initTrace(tb,
				List.of(
					"RIP = 0x00400000;",
					"RSP = 0x00110000;",
					"RAX = 0xff12345678;"),
				List.of(
					"DEC EAX",
					"MOV ECX,EAX"));
			// Assembly sanity check
			ByteBuffer buf = ByteBuffer.allocate(3);
			tb.trace.getMemoryManager().getBytes(0, tb.addr(0x00400000), buf);
			assertArrayEquals(tb.arr(0x48, 0x89, 0xc1), buf.array());

			TracePcodeEmulator emu = new TracePcodeEmulator(tb.trace, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.overrideContext(ctxVal);
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (UndoableTransaction tid = tb.startTransaction()) {
				emu.writeDown(tb.trace, 1, 1, false);
			}

			assertEquals(BigInteger.valueOf(0x00400003),
				TraceSleighUtils.evaluate("RIP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x12345677),
				TraceSleighUtils.evaluate("RCX", tb.trace, 1, thread, 0));
		}
	}
}
