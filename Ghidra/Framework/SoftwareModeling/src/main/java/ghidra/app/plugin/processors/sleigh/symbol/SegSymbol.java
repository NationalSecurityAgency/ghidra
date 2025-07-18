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
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.SegInstructionValue;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * Symbol with semantic value equal to the segment value of the
 * current instruction (seg_next)
 */
public class SegSymbol extends SpecificSymbol {

	private PatternExpression patexp;

	@Override
	public PatternExpression getPatternExpression() {
		return patexp;
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		hand.space = walker.getCurSpace();
		hand.offset_space = null;
		hand.offset_offset = walker.getSegaddr().getOffset();
		hand.size = hand.space.getPointerSize();
	}

	@Override
	public String print(ParserWalker walker) throws MemoryAccessException {
		long val = walker.getSegaddr().getOffset();
		return "0x" + Long.toHexString(val);
	}

	@Override
	public void printList(ParserWalker walker, ArrayList<Object> list) {
		list.add(walker.getParentHandle());
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int el = decoder.openElement(ELEM_SEG_SYM);
		patexp = new SegInstructionValue();
		decoder.closeElement(ELEM_SEG_SYM.id());
	}

} 