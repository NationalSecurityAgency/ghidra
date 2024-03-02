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
/*
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A pattern with no semantic or printing content, that will match
 * any pattern.
 */
public class EpsilonSymbol extends PatternlessSymbol {

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		hand.space = walker.getConstSpace();
		hand.offset_space = null;	// Not a dynamic value
		hand.offset_offset = 0;
		hand.size = 0;				// Cannot provide size
	}

	@Override
	public String print(ParserWalker walker) {
		return "0";
	}

	@Override
	public void printList(ParserWalker walker, ArrayList<Object> list) {
		list.add(walker.getParentHandle());
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int element = decoder.openElement(ELEM_EPSILON_SYM);
		decoder.closeElement(ELEM_EPSILON_SYM.id());
		// Nothing to do
	}

}
