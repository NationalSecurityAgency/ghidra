/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
/*
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.program.model.mem.*;
import ghidra.xml.*;

import java.util.*;

/**
 * 
 *
 * Symbol with semantic value equal to offset of address immediately
 * after current instruction
 */
public class EndSymbol extends SpecificSymbol {

	private PatternExpression patexp;
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#getPatternExpression()
	 */
	@Override
    public PatternExpression getPatternExpression() {
		return patexp;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#getFixedHandle(ghidra.app.plugin.processors.sleigh.FixedHandle, ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		hand.space = walker.getCurSpace();
		hand.offset_space = null;
		hand.offset_offset = walker.getNaddr().getOffset();
		hand.size = hand.space.getPointerSize();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#print(ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public String print(ParserWalker walker) throws MemoryAccessException {
		long val = walker.getNaddr().getOffset();
		return "0x"+Long.toHexString(val);
	}

	@Override
    public void printList(ParserWalker walker, ArrayList<Object> list) {
		list.add(walker.getParentHandle());
	}
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.Symbol#restoreXml(org.jdom.Element, ghidra.app.plugin.processors.sleigh.SleighLanguage)
	 */
	@Override
    public void restoreXml(XmlPullParser parser, SleighLanguage sleigh) {
	    XmlElement element = parser.start("end_sym");
		patexp = new EndInstructionValue();
		parser.end(element);
	}

}
