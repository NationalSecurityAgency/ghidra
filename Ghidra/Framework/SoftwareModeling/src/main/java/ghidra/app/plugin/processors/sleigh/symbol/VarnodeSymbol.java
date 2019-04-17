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
import ghidra.program.model.address.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

import java.util.*;

/**
 * 
 *
 * A symbol representing a global varnode, i.e. a named memory location
 */
public class VarnodeSymbol extends PatternlessSymbol {

	private VarnodeData fix;
	
	public VarnodeData getFixedVarnode() { return fix; }
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#getFixedHandle(ghidra.app.plugin.processors.sleigh.FixedHandle, ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		hand.space = fix.space;
		hand.offset_space = null;		// Not a dynamic variable
		hand.offset_offset = fix.offset;
		hand.size = fix.size;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#print(ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public String print(ParserWalker walker) {
		return getName();	// Use the symbol name for printing
	}

	@Override
    public void printList(ParserWalker walker, ArrayList<Object> list) {
		list.add(walker.getParentHandle());
	}
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.Symbol#restoreXml(org.jdom.Element, ghidra.program.model.address.AddressFactory)
	 */
	@Override
    public void restoreXml(XmlPullParser parser,SleighLanguage sleigh) {
	    XmlElement el = parser.start("varnode_sym");
		fix = new VarnodeData();
		AddressFactory factory = sleigh.getAddressFactory();
		fix.space = factory.getAddressSpace(el.getAttribute("space"));
		fix.offset = SpecXmlUtils.decodeLong(el.getAttribute("offset"));
		fix.size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
		// PatternlessSymbol does not need to be restored
		parser.end(el);
	}

}
