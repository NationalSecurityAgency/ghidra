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
package ghidra.pcode.emu.jit.analysis;

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.JitPassage;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.*;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import junit.framework.AssertionFailedError;

public class JitControlFlowModelTest extends AbstractJitTest {

	public static PcodeOp assertCopyConst(long imm, PcodeOp op) {
		assertOp(PcodeOp.COPY, op);
		Varnode input = op.getInput(0);
		assertTrue(input.isConstant());
		assertEquals(imm, input.getOffset());
		return op;
	}

	record ExpectedBlock(List<PcodeOp> ops) {
		public static ExpectedBlock sub(PcodeProgram program, PcodeOp start, PcodeOp endIncl) {
			int startIdx = program.getCode().indexOf(start);
			int endIdxIncl = program.getCode().indexOf(endIncl);
			return new ExpectedBlock(
				List.copyOf(program.getCode().subList(startIdx, endIdxIncl + 1)));
		}
	}

	enum BrType {
		INT, ERR, EXT, IND
	}

	enum BrFlow {
		BR, FT
	}

	record ExpectedBranch(PcodeOp from, PcodeOp to, BrType type, BrFlow flow, long addr) {}

	record From(PcodeOp op, BrFlow flow) {
		From {
			assertNotNull(op);
		}
	}

	public static class ExpectationsAsserter {
		private final List<ExpectedBlock> eBlocks;
		private final Set<ExpectedBranch> eBranches;
		private final JitControlFlowModel cfm;

		private final Map<PcodeOp, PcodeOp> opMap = new HashMap<>(); // because of rewrites
		private final Map<PcodeOp, JitBlock> aOpToBlock = new HashMap<>();

		private final Map<JitBlock, Set<ExpectedBranch>> eBranchesFrom = new HashMap<>();
		private final Map<JitBlock, Set<ExpectedBranch>> eBranchesTo = new HashMap<>();
		private final Map<JitBlock, Set<ExpectedBranch>> eBranchesOut = new HashMap<>();

		public ExpectationsAsserter(List<ExpectedBlock> eBlocks, Set<ExpectedBranch> eBranches,
				JitControlFlowModel cfm) {
			this.eBlocks = eBlocks;
			this.eBranches = eBranches;
			this.cfm = cfm;
		}

		public void assertOpEquivalence(PcodeOp eOp, PcodeOp aOp) {
			assertEquals("expected: %s but was: %s".formatted(
				PcodeOp.getMnemonic(eOp.getOpcode()),
				PcodeOp.getMnemonic(aOp.getOpcode())),
				eOp.getOpcode(), aOp.getOpcode());
			assertEquals(eOp.getOutput(), aOp.getOutput());
			assertEquals(eOp.getNumInputs(), aOp.getNumInputs());
			for (int i = 0; i < eOp.getNumInputs(); i++) {
				assertEquals(eOp.getInput(i), aOp.getInput(i));
			}
			opMap.put(eOp, aOp);
		}

		public void assertBlockEquivalence(ExpectedBlock eBlock, JitBlock aBlock) {
			assertEquals(eBlock.ops.size(), aBlock.getCode().size());
			for (int i = 0; i < eBlock.ops.size(); i++) {
				PcodeOp aOp = aBlock.getCode().get(i);
				assertOpEquivalence(eBlock.ops.get(i), aOp);
				aOpToBlock.put(aOp, aBlock);
			}
		}

		public void checkAndSortBranches() {
			for (ExpectedBranch eBranch : eBranches) {
				PcodeOp aFromOp = opMap.get(eBranch.from);
				JitBlock aFromBlock = aOpToBlock.get(aFromOp);
				assertEquals(aFromOp, aFromBlock.getCode().getLast());
				if (eBranch.to != null) {
					PcodeOp aToOp = opMap.get(eBranch.to);
					JitBlock aToBlock = aOpToBlock.get(aToOp);
					assertEquals(aToOp, aToBlock.getCode().getFirst());
					eBranchesFrom.computeIfAbsent(aFromBlock, fb -> new HashSet<>()).add(eBranch);
					eBranchesTo.computeIfAbsent(aToBlock, tb -> new HashSet<>()).add(eBranch);
				}
				else {
					eBranchesOut.computeIfAbsent(aFromBlock, fb -> new HashSet<>()).add(eBranch);
				}
			}
		}

		public void assertBranchEquivalence(ExpectedBranch eBranch, Branch aBranch) {
			assertEquals(opMap.get(eBranch.from), aBranch.from());
			assertEquals("expected: %s but was %s".formatted(eBranch, aBranch),
				eBranch.flow == BrFlow.FT, aBranch.isFall());
			switch (eBranch.type) {
				case INT -> {
					if (!(aBranch instanceof IntBranch ib)) {
						throw new AssertionFailedError();
					}
					assertEquals(opMap.get(eBranch.to), ib.to());
				}
				case ERR -> {
					if (!(aBranch instanceof ErrBranch)) {
						throw new AssertionFailedError();
					}
				}
				case EXT -> {
					if (!(aBranch instanceof ExtBranch ext)) {
						throw new AssertionFailedError();
					}
					assertEquals(eBranch.addr, ext.to().address.getOffset());
				}
				case IND -> {
					if (!(aBranch instanceof IndBranch)) {
						throw new AssertionFailedError();
					}
				}
				default -> throw new AssertionFailedError();
			}
		}

		public void assertBranchesEquivalent(Set<ExpectedBranch> eBranches,
				Set<? extends Branch> aBranches) {
			assertEquals("expected:" + eBranches + " but was " + aBranches, eBranches.size(),
				aBranches.size());
			Map<From, ? extends Branch> aBranchMap = aBranches.stream()
					.collect(Collectors.toMap(
						b -> new From(b.from(), b.isFall() ? BrFlow.FT : BrFlow.BR), b -> b));
			for (ExpectedBranch eBranch : eBranches) {
				Branch aBranch = aBranchMap.get(new From(opMap.get(eBranch.from), eBranch.flow));
				assertNotNull("Did not see expected branch " + eBranch + " in " + aBranches,
					aBranch);
				assertBranchEquivalence(eBranch, aBranch);
			}
		}

		public void assertBlockBranchEquivalence(ExpectedBlock eBlock, JitBlock aBlock) {
			assertBranchesEquivalent(eBranchesFrom.getOrDefault(aBlock, Set.of()),
				Set.copyOf(aBlock.branchesFrom()));
			assertBranchesEquivalent(eBranchesTo.getOrDefault(aBlock, Set.of()),
				Set.copyOf(aBlock.branchesTo()));
			assertBranchesEquivalent(eBranchesOut.getOrDefault(aBlock, Set.of()),
				Set.copyOf(aBlock.branchesOut()));
		}

		public void assertFlowEquivalence(ExpectedBranch eBranch, BlockFlow aFlow) {
			assertBranchEquivalence(eBranch, aFlow.branch());
			assertEquals(aOpToBlock.get(aFlow.branch().to()), aFlow.to());
		}

		public void assertFlowsEquivalent(Set<ExpectedBranch> eBranches, Set<BlockFlow> aFlows) {
			assertEquals(eBranches.size(), aFlows.size());
			Map<From, BlockFlow> aFlowMap = aFlows.stream()
					.collect(Collectors.toMap(b -> new From(b.branch().from(),
						b.branch().isFall() ? BrFlow.FT : BrFlow.BR), b -> b));
			for (ExpectedBranch eBranch : eBranches) {
				BlockFlow aFlow = aFlowMap.get(new From(opMap.get(eBranch.from), eBranch.flow));
				assertNotNull("Did not see expected flow " + eBranch + " in " + aFlows, aFlow);
				assertFlowEquivalence(eBranch, aFlow);
			}
		}

		public void assertBlockFlowEquivalence(ExpectedBlock eBlock, JitBlock aBlock) {
			assertFlowsEquivalent(eBranchesFrom.getOrDefault(aBlock, Set.of()),
				Set.copyOf(aBlock.flowsFrom().values()));
			assertFlowsEquivalent(eBranchesTo.getOrDefault(aBlock, Set.of()),
				Set.copyOf(aBlock.flowsTo().values()));
		}

		public void assertEquivalence() {
			List<JitBlock> aBlocks = List.copyOf(cfm.getBlocks());
			assertEquals(eBlocks.size(), aBlocks.size());
			for (int i = 0; i < eBlocks.size(); i++) {
				assertBlockEquivalence(eBlocks.get(i), aBlocks.get(i));
			}

			checkAndSortBranches();

			for (int i = 0; i < eBlocks.size(); i++) {
				assertBlockBranchEquivalence(eBlocks.get(i), aBlocks.get(i));
				assertBlockFlowEquivalence(eBlocks.get(i), aBlocks.get(i));
			}
		}
	}

	public static void assertCfmExpectations(List<ExpectedBlock> eBlocks,
			Set<ExpectedBranch> eBranches, JitControlFlowModel cfm) {
		new ExpectationsAsserter(eBlocks, eBranches, cfm).assertEquivalence();
	}

	@Test(expected = UnterminatedFlowException.class)
	public void testSingleBlockNoBranching() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = r1;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		new JitControlFlowModel(context);
	}

	@Test
	public void testSingleBlockTerminatingBranch() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, program.getCode().get(0));

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				new ExpectedBlock(List.of(opBranch))),
			Set.of(
				new ExpectedBranch(opBranch, null, BrType.EXT, BrFlow.BR, 0x1234)),
			cfm);
	}

	@Test
	public void testSingleBlockTerminatingConditionalBranch() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				if (r0) goto 0x5678;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		PcodeOp opCBranch = assertOp(PcodeOp.CBRANCH, program.getCode().get(0));
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, program.getCode().get(1));

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				new ExpectedBlock(List.of(opCBranch)),
				new ExpectedBlock(List.of(opBranch))),
			Set.of(
				new ExpectedBranch(opCBranch, null, BrType.EXT, BrFlow.BR, 0x5678),
				new ExpectedBranch(opCBranch, opBranch, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opBranch, null, BrType.EXT, BrFlow.BR, 0x1234)),
			cfm);
	}

	@Test
	public void testSingleBlockLoop() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				<L1>
				goto <L1>;
				""", PcodeUseropLibrary.NIL);
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, program.getCode().get(0));

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				new ExpectedBlock(List.of(opBranch))),
			Set.of(
				new ExpectedBranch(opBranch, opBranch, BrType.INT, BrFlow.BR, 0)),
			cfm);
	}

	@Test
	public void testSingleBlockConditionalLoop() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				<L1>
				if (r0) goto <L1>;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		PcodeOp opCBranch = assertOp(PcodeOp.CBRANCH, program.getCode().get(0));
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, program.getCode().get(1));

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				new ExpectedBlock(List.of(opCBranch)),
				new ExpectedBlock(List.of(opBranch))),
			Set.of(
				new ExpectedBranch(opCBranch, opCBranch, BrType.INT, BrFlow.BR, 0),
				new ExpectedBranch(opCBranch, opBranch, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opBranch, null, BrType.EXT, BrFlow.BR, 0x1234)),
			cfm);
	}

	@Test
	public void testDegenerateIf() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				if (r0) goto <L1>;
				<L1>
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		PcodeOp opCBranch = assertOp(PcodeOp.CBRANCH, program.getCode().get(0));
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, program.getCode().get(1));

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				new ExpectedBlock(List.of(opCBranch)),
				new ExpectedBlock(List.of(opBranch))),
			Set.of(
				new ExpectedBranch(opCBranch, opBranch, BrType.INT, BrFlow.BR, 0),
				new ExpectedBranch(opCBranch, opBranch, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opBranch, null, BrType.EXT, BrFlow.BR, 0x1234)),
			cfm);
	}

	@Test
	public void testIfWithManyOps() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				if (r0 == r1 + 0x12) goto <L1>;
				r1 = 1;
				r2 = 2;
				<L1>
				r3 = 3;
				r4 = 4;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		PcodeOp opFirst = program.getCode().get(0);
		PcodeOp opCBranch = assertOp(PcodeOp.CBRANCH, program.getCode().get(2));
		PcodeOp opAfterCBranch = assertCopyConst(1, program.getCode().get(3));
		PcodeOp opBeforeL1 = assertCopyConst(2, program.getCode().get(4));
		PcodeOp opAtL1 = assertCopyConst(3, program.getCode().get(5));
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, program.getCode().get(7));

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				ExpectedBlock.sub(program, opFirst, opCBranch),
				ExpectedBlock.sub(program, opAfterCBranch, opBeforeL1),
				ExpectedBlock.sub(program, opAtL1, opBranch)),
			Set.of(
				new ExpectedBranch(opCBranch, opAfterCBranch, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opCBranch, opAtL1, BrType.INT, BrFlow.BR, 0),
				new ExpectedBranch(opBeforeL1, opAtL1, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opBranch, null, BrType.EXT, BrFlow.BR, 0x1234)),
			cfm);
	}

	@Test
	public void testTwoInstructionsNoBranching() throws Exception {
		SleighLanguage language = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:default"));

		Address addr0 = language.getDefaultSpace().getAddress(0);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buf = new AssemblyBuffer(asm, addr0);
		buf.assemble("imm r0, #0x123");
		buf.assemble("add r0, r0");
		JitPassage passage = decodePassage(buf);
		PcodeOp opLast = assertOp(PcodeOp.UNIMPLEMENTED, passage.getCode().getLast());

		JitAnalysisContext context = makeContext(passage);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				new ExpectedBlock(passage.getCode())),
			Set.of(
				new ExpectedBranch(opLast, null, BrType.ERR, BrFlow.BR, 0x4)),
			cfm);
	}

	@Test
	public void testInstructionsConditionalBranch() throws Exception {
		SleighLanguage language = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:default"));

		Address addr0 = language.getDefaultSpace().getAddress(0);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buf = new AssemblyBuffer(asm, addr0);
		Address patchAt = buf.getNext();
		buf.assemble("breq 0"); // Uses CBRANCH to skip BRANCH 
		buf.assemble("imm r0, #123");
		Address breqTo = buf.getNext();
		buf.assemble("add r0, r0");
		buf.assemble(patchAt, "breq 0x%x".formatted(breqTo.getOffset()));
		JitPassage passage = decodePassage(buf);
		// For sanity, and so I can reason out the results
		assertEquals("""
				<JitPassage:
				  0,00000000.0: $U800:1 = BOOL_NEGATE Z
				  1,00000000.1: CBRANCH *[ram]0x2:8, $U800:1
				  2,00000000.2: BRANCH *[ram]0x4:8
				  3,00000002.0: C = COPY 0:1
				  4,00000002.1: V = COPY 0:1
				  5,00000002.2: r0 = COPY 0x7b:8
				  6,00000002.3: N = INT_SLESS r0, 0:8
				  7,00000002.4: Z = INT_EQUAL r0, 0:8
				  8,00000004.0: C = INT_CARRY r0, r0
				  9,00000004.1: V = INT_SCARRY r0, r0
				  10,00000004.2: r0 = INT_ADD r0, r0
				  11,00000004.3: N = INT_SLESS r0, 0:8
				  12,00000004.4: Z = INT_EQUAL r0, 0:8
				  13,00000006.0: UNIMPLEMENTED
				>""", passage.format(true));
		PcodeOp opFirst = passage.getCode().getFirst();
		PcodeOp opCBranch = assertOp(PcodeOp.CBRANCH, passage.getCode().get(1));
		PcodeOp opBranch = assertOp(PcodeOp.BRANCH, passage.getCode().get(2));
		PcodeOp opStartImm = assertCopyConst(0, passage.getCode().get(3));
		PcodeOp opEndImm = assertOp(PcodeOp.INT_EQUAL, passage.getCode().get(7));
		PcodeOp opStartAdd = assertOp(PcodeOp.INT_CARRY, passage.getCode().get(8));
		PcodeOp opLast = assertOp(PcodeOp.UNIMPLEMENTED, passage.getCode().getLast());

		JitAnalysisContext context = makeContext(passage);
		JitControlFlowModel cfm = new JitControlFlowModel(context);

		assertCfmExpectations(
			List.of(
				ExpectedBlock.sub(passage, opFirst, opCBranch),
				ExpectedBlock.sub(passage, opBranch, opBranch),
				ExpectedBlock.sub(passage, opStartImm, opEndImm),
				ExpectedBlock.sub(passage, opStartAdd, opLast)),
			Set.of(
				new ExpectedBranch(opCBranch, opStartImm, BrType.INT, BrFlow.BR, 0),
				new ExpectedBranch(opCBranch, opBranch, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opBranch, opStartAdd, BrType.INT, BrFlow.BR, 0),
				new ExpectedBranch(opEndImm, opStartAdd, BrType.INT, BrFlow.FT, 0),
				new ExpectedBranch(opLast, null, BrType.ERR, BrFlow.BR, 0)),
			cfm);
	}
}
