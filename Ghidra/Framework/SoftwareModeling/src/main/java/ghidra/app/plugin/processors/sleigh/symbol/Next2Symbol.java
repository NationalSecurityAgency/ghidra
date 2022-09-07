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

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.Next2InstructionValue;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Symbol with semantic value equal to offset of address immediately
 * after the next instruction (inst_next2)
 */
public class Next2Symbol extends SpecificSymbol {

	private PatternExpression patexp;
	
	@Override
    public PatternExpression getPatternExpression() {
		return patexp;
	}

	@Override
    public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		hand.space = walker.getCurSpace();
		hand.offset_space = null;
		hand.offset_offset = walker.getN2addr().getOffset();
		hand.size = hand.space.getPointerSize();
	}

	@Override
    public String print(ParserWalker walker) throws MemoryAccessException {
		long val = walker.getN2addr().getOffset();
		return "0x"+Long.toHexString(val);
	}

	@Override
    public void printList(ParserWalker walker, ArrayList<Object> list) {
		list.add(walker.getParentHandle());
	}

	@Override
    public void restoreXml(XmlPullParser parser, SleighLanguage sleigh) {
		XmlElement element = parser.start("next2_sym");
		patexp = new Next2InstructionValue();
		parser.end(element);
	}

}
