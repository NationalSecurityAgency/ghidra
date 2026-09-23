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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.hamcrest.Matchers;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.op.JitCopyOp;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class JitOpUseModelTest extends AbstractJitTest {

	static class Models {
		final JitControlFlowModel cfm;
		final JitDataFlowModel dfm;
		final JitReachabilityModel rm;
		final JitVarScopeModel vsm;
		final JitOpUseModel oum;

		public Models(JitAnalysisContext context) {
			this.cfm = new JitControlFlowModel(context);
			this.dfm = new JitDataFlowModel(context, cfm);
			this.rm = new JitReachabilityModel(context, cfm, dfm);
			this.vsm = new JitVarScopeModel(cfm, dfm, rm);
			this.oum = new JitOpUseModel(context, cfm, dfm, rm, vsm);
		}
	}

	public static class MyLib extends AnnotatedPcodeUseropLibrary<byte[]> {
		@PcodeUserop
		public void pcodeop_one(@OpState PcodeExecutorState<byte[]> state, @OpOutput Varnode out,
				Varnode in1) {
		}
	}

	MyLib lib = new MyLib();

	@Test
	public void testImmediateOverwrite() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				r0 = r1;
				r0 = r2;
				goto 0x1234;
				""", lib);
		Models m = new Models(context);

		PcodeOp copyOpR1 = assertOp(PcodeOp.COPY, context.getPassage().getCode().getFirst());
		assertFalse(m.oum.isUsed(m.dfm.getJitOp(copyOpR1)));

		PcodeOp copyOpR2 = assertOp(PcodeOp.COPY, context.getPassage().getCode().get(1));
		assertTrue(m.oum.isUsed(m.dfm.getJitOp(copyOpR2)));
	}

	/**
	 * Because the userop could technically access any varnode, then any live varnode at the time of
	 * the userop call must be considered used.
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testInterveningCallOther() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				r0 = r1;
				r0 = pcodeop_one(r1);
				goto 0x1234;
				""", lib);
		Models m = new Models(context);

		PcodeOp copyOp = assertOp(PcodeOp.COPY, context.getPassage().getCode().getFirst());
		assertTrue(m.oum.isUsed(m.dfm.getJitOp(copyOp)));

		PcodeOp callotherOp = assertOp(PcodeOp.CALLOTHER, context.getPassage().getCode().get(1));
		assertTrue(m.oum.isUsed(m.dfm.getJitOp(callotherOp)));
	}

	@Test
	public void testConstantFoldingRewriteCopyConst() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				r0 = 0x10;
				r0 = r0 + r0;
				goto 0x1234;
				""", lib);
		Models m = new Models(context);

		PcodeOp copyOp = assertOp(PcodeOp.COPY, context.getPassage().getCode().getFirst());
		JitOp jitCopyOp = m.dfm.getJitOp(copyOp);
		assertThat(jitCopyOp, Matchers.instanceOf(JitCopyOp.class));
		assertFalse(m.oum.isUsed(jitCopyOp));

		PcodeOp addOp = assertOp(PcodeOp.INT_ADD, context.getPassage().getCode().get(1));
		JitOp jitAddOp = m.dfm.getJitOp(addOp);
		assertThat(jitAddOp, Matchers.instanceOf(JitCopyOp.class)); // re-written
		assertTrue(m.oum.isUsed(jitAddOp));
	}
}
