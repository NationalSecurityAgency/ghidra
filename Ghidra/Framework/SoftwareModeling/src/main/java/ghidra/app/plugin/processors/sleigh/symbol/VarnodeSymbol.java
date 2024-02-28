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
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A symbol representing a global varnode, i.e. a named memory location
 */
public class VarnodeSymbol extends PatternlessSymbol {

	private VarnodeData fix;

	public VarnodeData getFixedVarnode() {
		return fix;
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		hand.space = fix.space;
		hand.offset_space = null;		// Not a dynamic variable
		hand.offset_offset = fix.offset;
		hand.size = fix.size;
	}

	@Override
	public String print(ParserWalker walker) {
		return getName();	// Use the symbol name for printing
	}

	@Override
	public void printList(ParserWalker walker, ArrayList<Object> list) {
		list.add(walker.getParentHandle());
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int el = decoder.openElement(ELEM_VARNODE_SYM);
		fix = new VarnodeData();
		fix.space = decoder.readSpace(ATTRIB_SPACE);
		fix.offset = decoder.readUnsignedInteger(ATTRIB_OFF);
		fix.size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
		decoder.closeElement(ELEM_VARNODE_SYM.id());
	}

}
