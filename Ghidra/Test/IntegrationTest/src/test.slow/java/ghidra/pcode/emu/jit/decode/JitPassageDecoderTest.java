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
package ghidra.pcode.emu.jit.decode;

import static org.junit.Assert.assertNull;

import java.util.Map.Entry;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.JitPassage.Operand;
import ghidra.pcode.emu.jit.analysis.JitAnalysisContext;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.pcode.PcodeOp;

public class JitPassageDecoderTest extends AbstractJitTest {
	void dumpFolded(JitAnalysisContext context) {
		SleighLanguage language = context.getLanguage();
		for (Entry<Operand, byte[]> ent : context.getPassage().allFoldedOperands().entrySet()) {
			byte[] v = ent.getValue();
			Operand k = ent.getKey();
			System.err.println("%s %s=0x%s".formatted(k.op().getSeqnum(), k,
				Utils.bytesToBigInteger(v, v.length, language.isBigEndian(), false).toString(16)));
		}
	}

	@Test
	public void testRevalidationSimpleCBranch() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();
		JitAnalysisContext context = makeContext(language, """
				local base:8 = 0x6000;
				local off:8 = 0;
				<loop>
				  local addr:8 = base + off;
				  off = off + 1;
				if off < 0x100 goto <loop>;
				""", PcodeUseropLibrary.nil());

		PcodeOp addOp = assertOp(PcodeOp.INT_ADD, context.getPassage().getCode().get(2));
		byte[] constAddr = context.getPassage().getFoldedOperand(addOp, -1);
		assertNull(constAddr);
	}

	@Test
	public void testRevalidationCBranchOverBranch() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();
		JitAnalysisContext context = makeContext(language, """
				local base:8 = 0x6000;
				local off:8 = 0;
				<loop>
				  local addr:8 = base + off;
				  off = off + 1;
				if off > 0x100 goto <exit>;
				goto <loop>;
				<exit>
				""", PcodeUseropLibrary.nil());

		PcodeOp addOp = assertOp(PcodeOp.INT_ADD, context.getPassage().getCode().get(2));
		JitOp.toString(addOp, PcodeUseropLibrary.nil().getSymbols(language));
		byte[] constAddr = context.getPassage().getFoldedOperand(addOp, -1);
		assertNull(constAddr);
	}
}
