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
package ghidra.pcode.emu;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.SystemUtilities;

public abstract class AbstractPcodeEmulatorTest extends AbstractGTest {

	protected abstract PcodeEmulator createEmulator(Language language);

	public static final LanguageID LANGID_TOY_BE = new LanguageID("Toy:BE:64:default");
	public static final LanguageID LANGID_TOY_LE = new LanguageID("Toy:BE:64:default");
	public static final LanguageID LANGID_X64 = new LanguageID("x86:LE:64:default");
	public static final LanguageID LANGID_ARMV8 = new LanguageID("ARM:LE:32:v8");

	public static final int FIB_ITER_N = 100000;
	public static final long FIB_ITER_VAL = 2754320626097736315L;

	public static final int FIB_REC_N = 25;
	public static final long FIB_REC_VAL = 75025;

	public static int getFibIterN() {
		if (SystemUtilities.isInTestingBatchMode()) {
			return 10;
		}
		return FIB_ITER_N;
	}

	public static long getFibIterVal() {
		if (SystemUtilities.isInTestingBatchMode()) {
			return 55;
		}
		return FIB_ITER_VAL;
	}

	public static int getFibRecN() {
		if (SystemUtilities.isInTestingBatchMode()) {
			return 10;
		}
		return FIB_REC_N;
	}

	public static long getFibRecVal() {
		if (SystemUtilities.isInTestingBatchMode()) {
			return 55;
		}
		return FIB_REC_VAL;
	}

	public static Language getLanguage(LanguageID id) throws LanguageNotFoundException {
		return DefaultLanguageService.getLanguageService().getLanguage(id);
	}

	@Before
	public void setUp() throws IOException {
		if (!Application.isInitialized()) {
			Application.initializeApplication(
				new GhidraTestApplicationLayout(new File(getTestDirectoryPath())),
				new ApplicationConfiguration());
		}
	}

	@Test
	public void testRunFibonacciIterativeToy() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r1, #1");
		Address loop = asm.getNext();
		asm.assemble("mov r2, r0");
		asm.assemble("add r2, r1");
		asm.assemble("mov r0, r1");
		asm.assemble("mov r1, r2");
		asm.assemble("sub r3, #1");
		asm.assemble("brne 0x%s".formatted(loop));

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());

		Register r0 = emu.getLanguage().getRegister("r0");
		Register r3 = emu.getLanguage().getRegister("r3");

		thread.getState().setVar(r3, arithmetic.fromConst(getFibIterN(), 8));

		long start = System.currentTimeMillis();
		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
		}
		long time = System.currentTimeMillis() - start;

		System.out.println("Took %f seconds".formatted(time / 1000.0));

		assertEquals(getFibIterVal(),
			arithmetic.toLong(thread.getState().getVar(r0, Reason.INSPECT), Purpose.INSPECT));
	}

	@Test
	public void testRunFibonacciIterativeX64() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_X64));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("MOV RBX, 1");
		Address loop = asm.getNext();
		asm.assemble("LEA RDX, [RAX+RBX*1]");
		asm.assemble("MOV RAX, RBX");
		asm.assemble("MOV RBX, RDX");
		asm.assemble("DEC RCX");
		asm.assemble("JNZ 0x%s".formatted(loop));

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		thread.overrideContextWithDefault();

		Register rax = emu.getLanguage().getRegister("RAX");
		Register rcx = emu.getLanguage().getRegister("RCX");

		thread.getState().setVar(rcx, arithmetic.fromConst(getFibIterN(), 8));

		long start = System.currentTimeMillis();
		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
		}
		long time = System.currentTimeMillis() - start;

		System.out.println("Took %f seconds".formatted(time / 1000.0));

		assertEquals(getFibIterVal(),
			arithmetic.toLong(thread.getState().getVar(rax, Reason.INSPECT), Purpose.INSPECT));
	}

	@Test
	public void testRunFibonacciRecursiveX64() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_X64));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("CMP RCX, 1"); // n in RCX
		Address patchJbe = asm.getNext();
		asm.assemble("JBE 0x%s".formatted(asm.getNext())); // placeholder
		asm.assemble("PUSH R8"); // Temp to save n
		asm.assemble("PUSH R9"); // Temp to save fib(n-1) 
		asm.assemble("MOV R8, RCX");
		asm.assemble("DEC RCX");
		asm.assemble("CALL 0x%s".formatted(asm.getEntry()));
		asm.assemble("MOV R9, RAX");
		asm.assemble("LEA RCX, [R8 + -2]");
		asm.assemble("CALL 0x%s".formatted(asm.getEntry()));
		asm.assemble("ADD RAX, R9");
		asm.assemble("POP R9");
		asm.assemble("POP R8");
		asm.assemble("RET");
		Address jbeTarget = asm.getNext();
		asm.assemble("MOV RAX, RCX");
		asm.assemble("RET");

		asm.assemble(patchJbe, "JBE 0x%s".formatted(jbeTarget));

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());
		thread.overrideContextWithDefault();

		Register rax = emu.getLanguage().getRegister("RAX");
		Register rcx = emu.getLanguage().getRegister("RCX");

		thread.getState().setVar(rcx, arithmetic.fromConst(getFibRecN(), 8));

		long start = System.currentTimeMillis();
		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
		}
		long time = System.currentTimeMillis() - start;

		System.out.println("Took %f seconds".formatted(time / 1000.0));

		assertEquals(getFibRecVal(),
			arithmetic.toLong(thread.getState().getVar(rax, Reason.INSPECT), Purpose.INSPECT));
	}

	@Test
	public void testSwi() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r1, #1");
		Address brk = asm.getNext();
		asm.assemble("add r1, #1");

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());

		emu.addBreakpoint(brk, "1:1");

		try {
			thread.run();
			fail("Should have failed on breakpoint");
		}
		catch (InterruptPcodeExecutionException e) {
		}

		Register r1 = emu.getLanguage().getRegister("r1");
		assertEquals(1,
			arithmetic.toLong(thread.getState().getVar(r1, Reason.INSPECT), Purpose.INSPECT));
		assertEquals(brk, thread.getCounter());
	}

	@Test
	public void testInjectionError() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r1, #1");
		Address inject = asm.getNext();
		asm.assemble("add r1, #1");

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());

		emu.inject(inject, "emu_injection_err();");

		try {
			thread.run();
			fail("Should have failed on injection error");
		}
		catch (InjectionErrorPcodeExecutionException e) {
		}

		Register r1 = emu.getLanguage().getRegister("r1");
		assertEquals(1,
			arithmetic.toLong(thread.getState().getVar(r1, Reason.INSPECT), Purpose.INSPECT));
		assertEquals(inject, thread.getCounter());
	}

	@Test
	public void testSkipThumbStaysThumb() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_ARMV8));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		Address entry = space.getAddress(0x00400000);
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()), entry);

		Language language = asm.getAssembler().getLanguage();
		Register regCtx = language.getContextBaseRegister();
		Register regT = language.getRegister("T");
		RegisterValue rvDefault = new RegisterValue(regCtx,
			asm.getAssembler().getContextAt(asm.getNext()).toBigInteger(regCtx.getNumBytes()));
		RegisterValue rvThumb = rvDefault.assign(regT, BigInteger.ONE);
		AssemblyPatternBlock ctxThumb = AssemblyPatternBlock.fromRegisterValue(rvThumb);

		Address addrBlx = asm.getNext();
		asm.assemble("blx 0x0");
		Address addrThumb = asm.getNext();
		asm.assemble("hlt 1", ctxThumb);
		Address addrB = asm.getNext();
		asm.assemble("b 0x%s".formatted(entry), ctxThumb); // placeholder
		asm.assemble("adds r0, #0x1", ctxThumb); // Never executed
		Address addrTgt = asm.getNext();
		asm.assemble("adds r1, #0x1", ctxThumb);
		Address addrEnd = asm.getNext();

		// NOTE: blx [addr] always changes the instruction set
		asm.assemble(addrBlx, "blx 0x%s".formatted(addrThumb));
		asm.assemble(addrB, "b 0x%s".formatted(addrTgt), ctxThumb);

		// Skip the HLT instruction
		emu.inject(addrThumb, "goto 0x%s[ram];".formatted(addrB));

		byte[] bytes = asm.getBytes();
		// Sanity check regarding instruction encoding
		assertEquals(12, bytes.length);

		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(entry);
		thread.overrideContextWithDefault();

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			assertEquals(addrEnd, e.getProgramCounter());
		}

		Register r0 = emu.getLanguage().getRegister("r0");
		Register r1 = emu.getLanguage().getRegister("r1");

		assertEquals(0,
			arithmetic.toLong(thread.getState().getVar(r0, Reason.INSPECT), Purpose.INSPECT));
		assertEquals(1,
			arithmetic.toLong(thread.getState().getVar(r1, Reason.INSPECT), Purpose.INSPECT));
	}

	@Test
	public void testInjectedBranch() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r1, #1");
		Address inject = asm.getNext();
		asm.assemble("add r1, #1");
		Address target = asm.getNext();

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());

		emu.inject(inject, "goto 0x%08x;".formatted(target.getOffset()));

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			// Space assertion is subsumed by counter assertion
		}

		Register r1 = emu.getLanguage().getRegister("r1");
		assertEquals(1,
			arithmetic.toLong(thread.getState().getVar(r1, Reason.INSPECT), Purpose.INSPECT));
		assertEquals(target, thread.getCounter());
	}

	@Test
	public void testInjectedIndirectBranch() throws Exception {
		PcodeEmulator emu = createEmulator(getLanguage(LANGID_TOY_BE));
		PcodeArithmetic<byte[]> arithmetic = emu.getArithmetic();
		AddressSpace space = emu.getLanguage().getDefaultSpace();
		AssemblyBuffer asm = new AssemblyBuffer(Assemblers.getAssembler(emu.getLanguage()),
			space.getAddress(0x00400000));

		asm.assemble("imm r1, #1");
		Address inject = asm.getNext();
		asm.assemble("add r1, #1");
		Address target = asm.getNext();

		byte[] bytes = asm.getBytes();
		emu.getSharedState().setVar(asm.getEntry(), bytes.length, false, bytes);
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(asm.getEntry());

		emu.inject(inject, """
				r2 = 0x%08x;
				goto [r2];
				""".formatted(target.getOffset()));

		try {
			thread.run();
			fail("Should have crashed on decode error");
		}
		catch (DecodePcodeExecutionException e) {
			// Space assertion is subsumed by counter assertion
		}

		Register r1 = emu.getLanguage().getRegister("r1");
		assertEquals(1,
			arithmetic.toLong(thread.getState().getVar(r1, Reason.INSPECT), Purpose.INSPECT));
		assertEquals(target, thread.getCounter());
	}
}
