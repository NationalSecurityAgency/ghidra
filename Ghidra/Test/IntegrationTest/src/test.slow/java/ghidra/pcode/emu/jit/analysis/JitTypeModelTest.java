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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType;
import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitConstVal;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.*;
import ghidra.program.model.pcode.PcodeOp;

public class JitTypeModelTest extends AbstractJitTest {
	static class Models {
		final JitControlFlowModel cfm;
		final JitDataFlowModel dfm;
		final JitReachabilityModel rm;
		final JitVarScopeModel vsm;
		final JitOpUseModel oum;
		final JitTypeModel tm;

		public Models(JitAnalysisContext context) {
			cfm = new JitControlFlowModel(context);
			dfm = new JitDataFlowModel(context, cfm);
			rm = new JitReachabilityModel(context, cfm, dfm);
			vsm = new JitVarScopeModel(cfm, dfm, rm);
			oum = new JitOpUseModel(context, cfm, dfm, rm, vsm);
			oum.dumpResult();
			tm = new JitTypeModel(dfm, oum);
		}
	}

	@Test
	public void testDefault() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = r1;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		JitBlock block = Unique.assertOne(m.cfm.getBlocks());
		JitVal r0 = Unique.assertOne(m.dfm.getOutput(block, language.getRegister("r0")));
		assertEquals(LongJitType.I8, m.tm.typeOf(r0));
	}

	@Test
	public void testFloatThroughTerminalCopy() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r1 = r1 f+ r1;
				r0 = r1;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		JitBlock block = Unique.assertOne(m.cfm.getBlocks());
		JitVal r0 = Unique.assertOne(m.dfm.getOutput(block, language.getRegister("r0")));
		assertEquals(DoubleJitType.F8, m.tm.typeOf(r0));
	}

	@Test
	public void testFloatConstant() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = r1 f+ 0x5678;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		PcodeOp op = assertOp(PcodeOp.FLOAT_ADD, context.getPassage().getCode().getFirst());
		JitFloatAddOp fAddOp = (JitFloatAddOp) m.dfm.getJitOp(op);
		JitConstVal c1234 = (JitConstVal) fAddOp.r();
		assertEquals(DoubleJitType.F8, m.tm.typeOf(c1234));
	}

	@Test
	public void testCBranchInput() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				<loop>
				if (r0) goto <loop>;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		PcodeOp op = assertOp(PcodeOp.CBRANCH, context.getPassage().getCode().getFirst());
		JitCBranchOp cbranch = (JitCBranchOp) m.dfm.getJitOp(op);
		JitVal r0 = cbranch.cond();
		assertEquals(LongJitType.I8, m.tm.typeOf(r0));
	}

	@Test
	public void testBranchIndInput() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				goto [r0];
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		PcodeOp op = Unique.assertOne(context.getPassage().getCode());
		JitBranchIndOp branchind = (JitBranchIndOp) m.dfm.getJitOp(op);
		JitVal r0 = branchind.target();
		assertEquals(LongJitType.I8, m.tm.typeOf(r0));
	}

	@Test
	public void testLoop() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		/**
		 * Use conditional branch here otherwise, r0 appears unused and receives no type assignment.
		 * 
		 * The condition cannot be r0, because it wants to assign INTEGER.
		 */
		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				<loop>
				r0 = r0 f+ r1;
				if r1 goto <loop>;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		JitBlock block = m.cfm.getBlocks().iterator().next();
		JitVal r0 = Unique.assertOne(m.dfm.getOutput(block, language.getRegister("r0")));
		assertEquals(DoubleJitType.F8, m.tm.typeOf(r0));
	}

	@Test
	public void testViaSharedUse() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = r0 f+ r1;
				r2 = r1;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		Models m = new Models(context);

		JitBlock block = Unique.assertOne(m.cfm.getBlocks());
		JitVal r0 = Unique.assertOne(m.dfm.getOutput(block, language.getRegister("r0")));
		assertEquals(DoubleJitType.F8, m.tm.typeOf(r0));
		JitVal r2 = Unique.assertOne(m.dfm.getOutput(block, language.getRegister("r2")));
		assertEquals(DoubleJitType.F8, m.tm.typeOf(r2));
	}
}
