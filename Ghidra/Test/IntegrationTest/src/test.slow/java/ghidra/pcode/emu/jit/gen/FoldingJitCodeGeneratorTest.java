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
package ghidra.pcode.emu.jit.gen;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.lang.classfile.*;
import java.util.List;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.jit.analysis.JitTypeModel;
import ghidra.pcode.emu.jit.analysis.JitVarScopeModel;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.PcodeOp;

public class FoldingJitCodeGeneratorTest extends AbstractJitCodeGeneratorTest {

	protected static final LanguageID ID_TOYBE64 = new LanguageID("Toy:BE:64:default");
	protected static final LanguageID ID_TOYLE64 = new LanguageID("Toy:LE:64:default");

	protected Endian getEndian() {
		return Endian.BIG;
	}

	@Override
	protected LanguageID getLanguageID() {
		return switch (getEndian()) {
			case BIG -> ID_TOYBE64;
			case LITTLE -> ID_TOYLE64;
		};
	}

	@Test
	public void testBranchIndRewriteToDirectInternal() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				imm r0,#6
				br r0
				""", Map.of());
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opBranchInd = tr.uniqueOp(PcodeOp.BRANCHIND);
		List<CodeElement> codeForBranch = tr.codeForOp(cm, opBranchInd);
		Instruction firstCfi = firstControlFlowInstruction(codeForBranch);
		// As if internal unconditional branch, which uses goto
		assertEquals(Opcode.GOTO, firstCfi.opcode());
	}

	@Test
	public void testBranchIndNotRewritten() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				br r0
				""", Map.of());
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opBranchInd = tr.uniqueOp(PcodeOp.BRANCHIND);
		List<CodeElement> codeForBranch = tr.codeForOp(cm, opBranchInd);
		Instruction firstCfi = firstControlFlowInstruction(codeForBranch);
		// Indirect branch writes counter/context and returns null
		assertEquals(Opcode.ARETURN, firstCfi.opcode());
	}

	@Test
	public void testBranchIndRewrittenToConditionalDirectInternal() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				imm r0, #0
				imm r1, #1
				imm r2, #6

				add r0, r1
				cmp r0, r2
				brne 0x00400006

				br r0
				""", Map.of());
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opBranchInd = tr.uniqueOp(PcodeOp.BRANCHIND);
		List<CodeElement> codeForBranch = tr.codeForOp(cm, opBranchInd);
		Instruction firstCfi = firstControlFlowInstruction(codeForBranch);
		assertThat(firstCfi.opcode(), Matchers.oneOf(Opcode.IFEQ, Opcode.IFNE));
	}

	@Test
	public void testCBranchRewrittenToBranch() throws Exception {
		// Two vars, because a==a could be optimized later, regardless of A's constness
		Translation tr = translateSleigh(getLanguageID(), """
				local a:4 = 0;
				local b:4 = 0;
				if a==b goto <L1>;
				  r0 = 1;
				<L1>
				""");
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opCBranch = tr.uniqueOp(PcodeOp.CBRANCH);
		List<CodeElement> codeForBranch = tr.codeForOp(cm, opCBranch);
		Instruction firstCfi = firstControlFlowInstruction(codeForBranch);
		// Re-written as unconditional, so goto
		assertEquals(Opcode.GOTO, firstCfi.opcode());

		tr.runFallthrough();
		assertEquals(0, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCBranchRewrittenToNop() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				local a:4 = 0;
				local b:4 = 1;
				if a==b goto <L1>;
				  r0 = 1;
				<L1>
				""");
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opCBranch = tr.uniqueOp(PcodeOp.CBRANCH);
		List<CodeElement> codeForBranch = tr.codeForOp(cm, opCBranch);
		// Re-written as nop
		assertEquals(List.of(), codeForBranch);

		tr.runFallthrough();
		assertEquals(1, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCBranchNotRewritten() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = 0;
				<L1>
				  r0 = r0 + 1;
				if r0 != 6 goto <L1>;
				""");
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opCBranch = tr.uniqueOp(PcodeOp.CBRANCH);
		List<CodeElement> codeForBranch = tr.codeForOp(cm, opCBranch);
		Instruction firstCfi = firstControlFlowInstruction(codeForBranch);
		// Still conditional
		assertThat(firstCfi.opcode(), Matchers.oneOf(Opcode.IFEQ, Opcode.IFNE));

		// Emu initialized a and b to 0, but JIT doesn't know or care
		tr.runFallthrough();
		assertEquals(6, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCBranchRewrittenToBranchFallRemoved() throws Exception {
		// Two vars, because a==a could be optimized later, regardless of A's constness
		Translation tr = translateSleigh(getLanguageID(), """
				local a:4 = 0;
				local b:4 = 0;
				if a==b goto <L1>;
				  r0 = 1;
				goto <L2>;
				<L1>
				  r1 = 1;
				<L2>
				""");
		tr.runFallthrough();
		assertEquals(0, tr.getLongRegVal("r0"));
		assertEquals(1, tr.getLongRegVal("r1"));

		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opR0Copy1 = tr.uniqueCopyTo("r0");
		List<CodeElement> codeForCopyR0 = tr.codeForOp(cm, opR0Copy1);
		assertEquals(List.of(), codeForCopyR0);
		PcodeOp opR1Copy1 = tr.uniqueCopyTo("r1");
		List<CodeElement> codeForCopyR1 = tr.codeForOp(cm, opR1Copy1);
		assertNotEquals(List.of(), codeForCopyR1);
	}

	@Test
	public void testCBranchRewrittenToNopJumpRemoved() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				local a:4 = 0;
				local b:4 = 1;
				if a==b goto <L1>;
				  r0 = 1;
				goto <L2>;
				<L1>
				  r1 = 1;
				<L2>
				""");
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeOp opR0Copy1 = tr.uniqueCopyTo("r0");
		List<CodeElement> codeForCopyR0 = tr.codeForOp(cm, opR0Copy1);
		assertNotEquals(List.of(), codeForCopyR0);
		PcodeOp opR1Copy1 = tr.uniqueCopyTo("r1");
		List<CodeElement> codeForCopyR1 = tr.codeForOp(cm, opR1Copy1);
		assertEquals(List.of(), codeForCopyR1);

		tr.runFallthrough();
		assertEquals(1, tr.getLongRegVal("r0"));
		assertEquals(0, tr.getLongRegVal("r1"));
	}

	static final List<Integer> CONSTS =
		List.of(0x12, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xfa, 0xce);

	/**
	 * There's a lesson learned here when writing such chains e.g., in a syscall handler userop.
	 * Avoid allocation of disposable uniques. Use "local" to manually allocate and re-use uniques,
	 * but be careful to consider how the {@link JitTypeModel} will treat them.
	 * <p>
	 * LATER: Can we be more clever about which uniques actually need saving? Could be limited to
	 * those from a constructor offering a named block (for crossbuild elsewhere.) We have to
	 * consider whether it's possible for a unique to be retired and re-birthed within the same
	 * inject or instruction p-code. I <em>think</em> the current {@link JitVarScopeModel} prohibits
	 * this, but that could change.
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testCBranchChainCollapsed() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = 5;
				local z:1;
				z=r0==1; if z goto <L1>;
				z=r0==2; if z goto <L2>;
				z=r0==3; if z goto <L3>;
				z=r0==4; if z goto <L4>;
				z=r0==5; if z goto <L5>;
				z=r0==6; if z goto <L6>;
				z=r0==7; if z goto <L7>;
				z=r0==8; if z goto <L8>;
				     r1 = 0x12; goto <exit>;
				<L1> r1 = 0xde; goto <exit>;
				<L2> r1 = 0xad; goto <exit>;
				<L3> r1 = 0xbe; goto <exit>;
				<L4> r1 = 0xef; goto <exit>;
				<L5> r1 = 0xca; goto <exit>;
				<L6> r1 = 0xfe; goto <exit>;
				<L7> r1 = 0xfa; goto <exit>;
				<L8> r1 = 0xce;
				<exit>
				""");
		ClassModel cm = ClassFile.of().parse(tr.classbytes());
		PcodeProgram program = tr.program();
		SleighLanguage language = program.getLanguage();

		for (int i = 1; i <= 8; i++) {
			int idxIntEqual = i * 2 - 1;
			int idxCBranch = i * 2;
			PcodeOp opIntEqual = assertOp(PcodeOp.INT_EQUAL, program.getCode().get(idxIntEqual));
			assertEquals("r0", opIntEqual.getInput(0).toString(language));
			assertEquals("0x%x".formatted(i), opIntEqual.getInput(1).toString(language));
			PcodeOp opCBranch = assertOp(PcodeOp.CBRANCH, program.getCode().get(idxCBranch));
			if (i == 5) {
				assertNotEquals(List.of(), tr.codeForOp(cm, opIntEqual));
				/**
				 * No assertion on CBRANCH being a GOTO. If that GOTO is to the next bytecode, it
				 * ought to be removed.
				 */
			}
			else {
				assertEquals(List.of(), tr.codeForOp(cm, opIntEqual));
				assertEquals(List.of(), tr.codeForOp(cm, opCBranch));
			}
		}

		for (int i = 0; i <= 8; i++) {
			int idxCopy = i * 2 + 17;
			int idxBranch = i * 2 + 18;
			PcodeOp opCopy = assertOp(PcodeOp.COPY, program.getCode().get(idxCopy));
			assertEquals("r1", opCopy.getOutput().toString(language));
			assertEquals("0x%x".formatted(CONSTS.get(i)), opCopy.getInput(0).toString(language));
			PcodeOp opBranch =
				i == 8 ? null : assertOp(PcodeOp.BRANCH, program.getCode().get(idxBranch));
			if (i == 5) {
				assertNotEquals(List.of(), tr.codeForOp(cm, opCopy));
				/**
				 * No assertion on BRANCH being a GOTO. If that GOTO is to the next bytecode, it
				 * ought to be removed.
				 */
			}
			else {
				assertEquals(List.of(), tr.codeForOp(cm, opCopy));
				if (i != 8) {
					assertEquals(List.of(), tr.codeForOp(cm, opBranch));
				}
			}
		}

		tr.runFallthrough();
		assertEquals(5, tr.getLongRegVal("r0"));
		assertEquals(0xca, tr.getLongRegVal("r1"));

		assertEquals(
			List.of(
				new CountInvocation("Thread 0", 1, 3), // r0 = 5 and first cmp/cbranch
				new CountInvocation("Thread 0", 0, 8), // four collapsed cmp/cbranch blocks
				new CountInvocation("Thread 0", 0, 2), // r1 = 0xca; goto <exit>
				new CountInvocation("Thread 0", 0, 1)), // goto 0xdeadbeef
			countInvocations);
	}
}
