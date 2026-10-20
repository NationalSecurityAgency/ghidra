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

import java.util.List;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.pcode.PcodeOp;

public class JitReachabilityModelTest extends AbstractJitTest {

	static class Models {
		final JitControlFlowModel cfm;
		final JitDataFlowModel dfm;
		final JitReachabilityModel rm;

		public Models(JitAnalysisContext context) {
			this.cfm = new JitControlFlowModel(context);
			this.dfm = new JitDataFlowModel(context, cfm);
			dfm.dumpResult();
			this.rm = new JitReachabilityModel(context, cfm, dfm);
			rm.dumpResult();
		}
	}

	@Test
	public void testSingleBlock() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				goto 0x1234;
				""", PcodeUseropLibrary.nil());
		Models m = new Models(context);

		JitBlock block = Unique.assertOne(m.cfm.getBlocks());
		assertTrue(m.rm.isReachable(block));
	}

	@Test
	public void testCBranchNever() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				if 0:1 goto <L1>;
				  r0 = 1;
				<L1>
				goto 0x1234;
				""", PcodeUseropLibrary.nil());
		Models m = new Models(context);

		List<JitBlock> blocks = List.copyOf(m.cfm.getBlocks());
		assertOp(PcodeOp.CBRANCH, blocks.get(0).first());
		assertOp(PcodeOp.COPY, blocks.get(1).first());
		assertOp(PcodeOp.BRANCH, blocks.get(2).first());

		assertTrue(m.rm.isReachable(blocks.get(0)));
		assertTrue(m.rm.isReachable(blocks.get(1)));
		assertTrue(m.rm.isReachable(blocks.get(2)));

		assertTrue(m.rm.isTakeable(blocks.get(0).getFallFrom()));
		assertFalse(m.rm.isTakeable(blocks.get(0)
				.flowsFrom()
				.values()
				.stream()
				.filter(f -> !f.branch().isFall())
				.findAny()
				.orElseThrow()));
		assertTrue(m.rm.isTakeable(blocks.get(1).getFallFrom()));
	}

	@Test
	public void testCBranchAlways() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				if 1:1 goto <L1>;
				  r0 = 1;
				<L1>
				goto 0x1234;
				""", PcodeUseropLibrary.nil());
		Models m = new Models(context);

		List<JitBlock> blocks = List.copyOf(m.cfm.getBlocks());
		assertOp(PcodeOp.CBRANCH, blocks.get(0).first());
		assertOp(PcodeOp.COPY, blocks.get(1).first());
		assertOp(PcodeOp.BRANCH, blocks.get(2).first());

		assertTrue(m.rm.isReachable(blocks.get(0)));
		assertFalse(m.rm.isReachable(blocks.get(1)));
		assertTrue(m.rm.isReachable(blocks.get(2)));

		assertFalse(m.rm.isTakeable(blocks.get(0).getFallFrom()));
		assertTrue(m.rm.isTakeable(blocks.get(0)
				.flowsFrom()
				.values()
				.stream()
				.filter(f -> !f.branch().isFall())
				.findAny()
				.orElseThrow()));
		assertFalse(m.rm.isTakeable(blocks.get(1).getFallFrom()));
	}
}
