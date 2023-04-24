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
import java.util.List;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.lang.*;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.context.DBTraceRegisterContextManager;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.target.DBTraceObjectManagerTest;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.NumericUtilities;

public class BytesTracePcodeEmulatorTest extends AbstractTracePcodeEmulatorTest {

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
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					""",
				List.of(
					"PUSH 0xdeadbeef"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			// Verify no changes to trace
			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("RSP", tb.trace, 0, thread, 0));
			assertEquals(BigInteger.valueOf(0),
				TraceSleighUtils.evaluate("*:4 0x0010fffc:8", tb.trace, 0, thread, 0));

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			// 4, not 8 bytes pushed?
			assertEquals(BigInteger.valueOf(0x0010fffc),
				TraceSleighUtils.evaluate("RSP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0xdeadbeefL),
				TraceSleighUtils.evaluate("*:4 RSP", tb.trace, 1, thread, 0));
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
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					""",
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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

			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					RAX = 0x12345678;
					""",
				List.of(
					"JMP 0x00400007",       // 2 bytes
					"MOV EAX,0xdeadbeef",   // 5 bytes
					"MOV ECX,0xbaadf00d")); // 5 bytes

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00400007), emuThread.getCounter());
			assertArrayEquals(tb.arr(0x07, 0, 0x40, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(pc, Reason.INSPECT));

			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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
			// write 0x00401001 immediately after bx (0x00400008)
			TraceThread thread = initTrace(tb, """
					pc = 0x00400000;
					sp = 0x00110000;
					*:4 0x00400008:4 = 0x00401001;
					""",
				List.of(
					"ldr r6, [pc,#0]!", // 4 bytes,   pc+4 should be 00400008
					"bx r6"));          // 4 bytes

			byte[] mov = asm.assembleLine(tb.addr(0x00401000),
				"movs r0, #123", thumbPat); // #123 is decimal
			try (Transaction tx = tb.startTransaction()) {
				asm.patchProgram(mov, tb.addr(0x00401000));
			}

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00401000), emuThread.getCounter());
			assertArrayEquals(tb.arr(0, 0x10, 0x40, 0),
				emuThread.getState().getVar(pc, Reason.INSPECT));
			assertEquals(new RegisterValue(ctxreg, BigInteger.valueOf(0x8000_0000_0000_0000L)),
				emuThread.getContext());
			assertArrayEquals(tb.arr(0x80, 0, 0, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(ctxreg, Reason.INSPECT));

			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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

			TraceThread thread = initTrace(tb, """
					pc = 0x00400000;
					sp = 0x00110000;
					""",
				List.of(
					"imm r0, #911")); // decimal

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x00110000),
				TraceSleighUtils.evaluate("sp", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x00400002),
				TraceSleighUtils.evaluate("pc", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(911),
				TraceSleighUtils.evaluate("r0", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * This tests the delay-slot semantics of the emulator
	 */
	@Test
	public void testBRDS() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "Toy:BE:64:default")) {
			TraceThread thread = initTrace(tb, """
					pc = 0x00400000;
					sp = 0x00110000;
					""",
				List.of(
					"brds 0x00400006",
					"imm r0, #911", // decimal
					"imm r0, #860",
					"imm r1, #861"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction(); // brds and 1st imm executed
			emuThread.stepInstruction(); // 3rd imm executed

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x00400008),
				TraceSleighUtils.evaluate("pc", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(911),
				TraceSleighUtils.evaluate("r0", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(861),
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
	 * execution of each instruction. Addressing is computed by the Sleigh instruction parser and
	 * encoded as a constant deref in the p-code.
	 */
	@Test
	public void testSelfModifyingX86() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			// NB. Assembly actually happens first, so Sleigh will modify it
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					RAX = 0x12345678;
					*:1 0x00400007:8 = *0x00400007:8 ^ 0xcc;
					""",
				List.of(
					// First instruction undoes the modification above
					"XOR byte ptr [0x00400007], 0xcc",  // 7 bytes
					"MOV EAX,0xdeadbeef"));            // 5 bytes

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());

			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					""",
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
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

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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
			PcodeUseropLibrary<byte[]> hexLib = new AnnotatedPcodeUseropLibrary<byte[]>() {
				@Override
				protected Lookup getMethodLookup() {
					return MethodHandles.lookup();
				}

				@PcodeUserop
				public void hexdump(byte[] in) {
					dumped.append(NumericUtilities.convertBytesToString(in));
				}
			};
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					""",
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0) {
				@Override
				protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
					return hexLib;
				}
			};
			emu.inject(tb.addr(0x00400006), "hexdump(RSP);");
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());

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
			PcodeUseropLibrary<byte[]> hexLib = new AnnotatedPcodeUseropLibrary<byte[]>() {
				@Override
				protected Lookup getMethodLookup() {
					return MethodHandles.lookup();
				}

				@PcodeUserop
				public void hexdump(byte[] in) {
					dumped.append(NumericUtilities.convertBytesToString(in));
				}
			};
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					""",
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0) {
				@Override
				protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
					return hexLib;
				}
			};
			emu.inject(tb.addr(0x00400006), """
					hexdump(RSP);
					emu_swi();
					hexdump(RIP);
					emu_exec_decoded();
					hexdump(RIP);
					""");
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());

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

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					RAX = 0;
					""",
				List.of(
					"PUSH 0xdeadbeef",
					"PUSH 0xbaadf00d"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			emu.addBreakpoint(tb.addr(0x00400000), "RAX == 1");
			emu.addBreakpoint(tb.addr(0x00400006), "RAX == 0");
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());

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
			TraceThread thread = initTrace(tb, """
					pc = 0x00400000;
					sp = 0x00110000;
					r0 = 0x00008000;
					""",
				List.of(
					"clz r1, r0"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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

			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					*:8 0x00600008:8 = 0x0123456789abcdef;
					*:8 0x00600000:8 = 0xfedcba9876543210;
					""",
				List.of(
					"MOVAPS XMM0, xmmword ptr [0x00600000]"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00400007), emuThread.getCounter());
			assertArrayEquals(tb.arr(0x07, 0, 0x40, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(pc, Reason.INSPECT));

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
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

			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					RAX = 0x7fffffff;
					RCX = 4;
					""",
				List.of(
					"SAR EAX, CL"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			assertEquals(tb.addr(0x00400002), emuThread.getCounter());
			assertArrayEquals(tb.arr(0x02, 0, 0x40, 0, 0, 0, 0, 0),
				emuThread.getState().getVar(pc, Reason.INSPECT));

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x7ffffff),
				TraceSleighUtils.evaluate("RAX", tb.trace, 1, thread, 0));
		}
	}

	@Test
	public void testCachedReadAfterSmallWrite() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					RAX = 0x12345678;
					""",
				List.of(
					"XOR AH, AH",
					"MOV RCX, RAX"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x12340078),
				TraceSleighUtils.evaluate("RAX", tb.trace, 1, thread, 0));
		}
	}

	@Test
	public void testDEC_MOV_compat32() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			Language lang = tb.trace.getBaseLanguage();
			Register ctxReg = lang.getContextBaseRegister();
			Register longModeReg = lang.getRegister("longMode");
			RegisterValue ctxVal = new RegisterValue(ctxReg)
					.assign(longModeReg, BigInteger.ZERO);
			DBTraceRegisterContextManager ctxManager = tb.trace.getRegisterContextManager();
			try (Transaction tx = tb.startTransaction()) {
				ctxManager.setValue(lang, ctxVal, Lifespan.nowOn(0),
					tb.range(0x00400000, 0x00400002));
			}
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					RAX = 0xff12345678;
					""",
				List.of(
					"DEC EAX",
					"MOV ECX,EAX"));
			// Assembly sanity check
			ByteBuffer buf = ByteBuffer.allocate(3);
			tb.trace.getMemoryManager().getBytes(0, tb.addr(0x00400000), buf);
			assertArrayEquals(tb.arr(0x48, 0x89, 0xc1), buf.array());

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			// TODO: Seems the Trace-bound thread ought to know to do this in reInitialize()
			ctxVal = ctxManager.getValueWithDefault(tb.host, ctxReg, 0, tb.addr(0x00400000));
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x00400003),
				TraceSleighUtils.evaluate("RIP", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x12345677),
				TraceSleighUtils.evaluate("RCX", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test the read max boundary case
	 * 
	 * <p>
	 * This happens very easily when RBP is uninitialized, as code commonly uses negative offsets
	 * from RBP. The range will have upper endpoint {@code ULONG_MAX+1}, non-inclusive, which would
	 * crash, instead requiring some special logic.
	 */
	@Test
	public void testMOV_EAX_dword_RBPm4() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					*:4 (0:8-4) = 0x12345678;
					""",
				List.of(
					"MOV EAX, dword ptr [RBP + -0x4]"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x12345678),
				TraceSleighUtils.evaluate("EAX", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test the read wrap-around case for x86_64
	 * 
	 * <p>
	 * This tests a rare (I hope) case where a read would wrap around the address space: 2 bytes
	 * including the max address, and 2 bytes at the min address. I imagine the behavior here varies
	 * by architecture? TODO: For now, I think it's acceptable just to throw an exception, but in
	 * reality, we should probably handle it and allow some mechanism for architectures to forbid
	 * it, if that's in fact what they do.
	 */
	@Test(expected = PcodeExecutionException.class)
	public void testMOV_EAX_dword_RBPm2_x64() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					RSP = 0x00110000;
					""",
				List.of(
					"MOV EAX, dword ptr [RBP + -0x2]"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
		}
	}

	/**
	 * Test the read wrap-around case for x86 (32)
	 * 
	 * <p>
	 * This test ensures the rule applies for spaces smaller than 64 bits
	 */
	@Test(expected = PcodeExecutionException.class)
	public void testMOV_EAX_dword_EBPm2_x86() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:32:default")) {
			TraceThread thread = initTrace(tb, """
					EIP = 0x00400000;
					ESP = 0x00110000;
					""",
				List.of(
					"MOV EAX, dword ptr [EBP + -0x2]"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
		}
	}

	/**
	 * Test that unimplemented instructions (as opposed to instructions with no semantics) result in
	 * an interrupt.
	 */
	@Test(expected = PcodeExecutionException.class)
	public void testUNIMPL() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "Toy:BE:64:default")) {
			assertEquals(Register.NO_CONTEXT, tb.language.getContextBaseRegister());

			TraceThread thread = initTrace(tb, """
					pc = 0x00400000;
					sp = 0x00110000;
					""",
				List.of(
					"unimpl"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
		}
	}

	@Test(expected = DecodePcodeExecutionException.class)
	public void testUninitialized() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "Toy:BE:64:default")) {
			assertEquals(Register.NO_CONTEXT, tb.language.getContextBaseRegister());

			TraceThread thread = initTrace(tb, """
					pc = 0x00400000;
					sp = 0x00110000;
					""",
				List.of()); // An empty, uninitialized program

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();
		}
	}

	@Test
	public void testMov_w_mW1_W0() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "dsPIC33F:LE:24:default")) {
			Address textStart = tb.language.getDefaultSpace().getAddress(0x000100, true);
			// TODO: Where is the stack typically on this arch?
			Address stackStart = tb.language.getDefaultDataSpace().getAddress(0, true);
			TraceThread thread = initTrace(tb,
				new AddressRangeImpl(textStart, 0x200),
				new AddressRangeImpl(stackStart, 1), """
						PC = 0x000100;
						W1 = 0x0800;
						*[ram]:2 0x000800:3 = 0x1234;
						""",
				List.of(
					"mov.w [W1], W0"));

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(tb.host, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 1);
			}

			assertEquals(BigInteger.valueOf(0x000102),
				TraceSleighUtils.evaluate("PC", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x1234),
				TraceSleighUtils.evaluate("W0", tb.trace, 1, thread, 0));
			assertEquals(BigInteger.valueOf(0x0800),
				TraceSleighUtils.evaluate("W1", tb.trace, 1, thread, 0));
		}
	}

	/**
	 * Test a single instruction in guest mode without identical mapping
	 * 
	 * <p>
	 * This is a repeat of the {@link #testSinglePUSH()} test, but as a guest platform, where the
	 * guest is mapped to addresses with shifted offsets (not identical). This will ensure the
	 * translation is happening properly.
	 */
	@Test
	public void testGuestSinglePUSH() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "DATA:BE:64:default")) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			TraceThread thread;
			TraceGuestPlatform x64;
			try (Transaction tx = tb.startTransaction()) {
				SchemaContext ctx = XmlSchemaContext.deserialize(DBTraceObjectManagerTest.XML_CTX);
				DBTraceObjectManager objects = tb.trace.getObjectManager();
				objects.createRootObject(ctx.getSchema(new SchemaName("Session")));
				thread = tb.getOrAddThread("Targets[0].Threads[0]", 0);

				mm.addRegion("Targets[0].Memory[bin:.text]", Lifespan.nowOn(0),
					tb.range(0x00000000, 0x0000ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
				mm.addRegion("Targets[0].Memory[stack1]", Lifespan.nowOn(0),
					tb.range(0x20000000, 0x2000ffff),
					TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);

				x64 = tb.trace.getPlatformManager()
						.addGuestPlatform(getSLEIGH_X86_64_LANGUAGE().getDefaultCompilerSpec());
				x64.addMappedRegisterRange();
				x64.addMappedRange(tb.addr(0x00000000), tb.addr(x64, 0x00400000), 0x10000);
				x64.addMappedRange(tb.addr(0x20000000), tb.addr(x64, 0x00100000), 0x10000);
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers"))
						.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

				tb.exec(x64, 0, thread, 0, """
						RIP = 0x00400000;
						RSP = 0x00110000;
						""");

				Assembler asm = Assemblers.getAssembler(x64.getLanguage());
				AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(x64, 0x00400000));
				buf.assemble("PUSH 0xdeadbeef");
				mm.putBytes(0, tb.addr(0x00000000), ByteBuffer.wrap(buf.getBytes()));
			}

			BytesTracePcodeEmulator emu = new BytesTracePcodeEmulator(x64, 0);
			PcodeThread<byte[]> emuThread = emu.newThread(thread.getPath());
			emuThread.stepInstruction();

			String changedExpr = "*:4 0x2000fffc:8";
			// Verify no changes to trace
			TraceMemorySpace regs = mm.getMemoryRegisterSpace(thread, 0, false);
			assertEquals(BigInteger.valueOf(0x00110000),
				regs.getValue(x64, 0, tb.reg(x64, "RSP")).getUnsignedValue());
			assertEquals(BigInteger.valueOf(0),
				TraceSleighUtils.evaluate(changedExpr, tb.trace, 0, thread, 0));

			try (Transaction tx = tb.startTransaction()) {
				emu.writeDown(x64, 1, 1);
			}

			// 4, not 8 bytes pushed?
			assertEquals(BigInteger.valueOf(0x0010fffc),
				regs.getValue(x64, 1, tb.reg(x64, "RSP")).getUnsignedValue());
			assertEquals(BigInteger.valueOf(0xefbeaddeL), // Guest is LE, host is BE
				TraceSleighUtils.evaluate(changedExpr, tb.trace, 1, thread, 0));
		}
	}
}
