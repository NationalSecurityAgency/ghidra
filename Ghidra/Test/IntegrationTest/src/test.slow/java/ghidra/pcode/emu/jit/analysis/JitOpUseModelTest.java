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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class JitOpUseModelTest extends AbstractJitTest {

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
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		JitVarScopeModel vsm = new JitVarScopeModel(cfm, dfm);
		JitOpUseModel oum = new JitOpUseModel(context, cfm, dfm, vsm);

		PcodeOp copyOp = assertOp(PcodeOp.COPY, context.getPassage().getCode().getFirst());
		assertFalse(oum.isUsed(dfm.getJitOp(copyOp)));
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
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		JitVarScopeModel vsm = new JitVarScopeModel(cfm, dfm);
		JitOpUseModel oum = new JitOpUseModel(context, cfm, dfm, vsm);

		PcodeOp copyOp = assertOp(PcodeOp.COPY, context.getPassage().getCode().getFirst());
		assertTrue(oum.isUsed(dfm.getJitOp(copyOp)));
	}
}
