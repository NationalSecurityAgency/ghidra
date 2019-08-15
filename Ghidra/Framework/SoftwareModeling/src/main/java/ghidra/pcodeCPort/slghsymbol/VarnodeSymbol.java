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
package ghidra.pcodeCPort.slghsymbol;

import java.io.PrintStream;
import java.util.ArrayList;

import org.jdom.Element;

import generic.util.UnsignedDataUtils;
// A global varnode
import ghidra.pcodeCPort.context.*;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.semantics.ConstTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

public class VarnodeSymbol extends PatternlessSymbol {

	private VarnodeData fix = new VarnodeData();

	public VarnodeSymbol(Location location) {
		super(location);
	} // For use with restoreXml

	public void markAsContext() {
// note: this value was never read		
//		context_bits = true;
	}

	public VarnodeData getFixedVarnode() {
		return fix;
	}

	@Override
	public int getSize() {
		return fix.size;
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		s.append(getName());
	}

	@Override
	public void collectLocalValues(ArrayList<Long> results) {
		if (fix.space.getType() == spacetype.IPTR_INTERNAL) {
			results.add(fix.offset);
		}
	}

	@Override
	public symbol_type getType() {
		return symbol_type.varnode_symbol;
	}

	public VarnodeSymbol(Location location, String nm, AddrSpace base, long offset, int size) {
		super(location, nm);
		int addrSize = base.getAddrSize();
		long maxByteOffset = ((long) base.getWordSize() << (8 * addrSize)) - 1;
		long endOffset = offset + size - 1;
		boolean sizeError = size != 0 && UnsignedDataUtils.unsignedGreaterThan(offset, endOffset);
		if (!sizeError && addrSize < 8) {
			sizeError = UnsignedDataUtils.unsignedGreaterThan(endOffset, maxByteOffset);
		}
		if (sizeError) {
			throw new SleighError(nm + ":" + size + " @ " + base.getName() + ":" +
				String.format("0x%x", offset) + " extends beyond end of space (max offset is " +
				String.format("0x%x", maxByteOffset) + ")", location);
		}

		fix.space = base;
		fix.offset = offset;
		fix.size = size;
	}

	@Override
	public VarnodeTpl getVarnode() {
		return new VarnodeTpl(location, new ConstTpl(fix.space),
			new ConstTpl(ConstTpl.const_type.real, fix.offset),
			new ConstTpl(ConstTpl.const_type.real, fix.size));
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker pos) {
		hand.space = fix.space;
		hand.offset_space = null; // Not a dynamic symbol
		hand.offset_offset = fix.offset;
		hand.size = fix.size;
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<varnode_sym");
		saveSleighSymbolXmlHeader(s);
		s.append(" space=\"").append(fix.space.getName()).append("\"");
		s.append(" offset=\"0x").append(Long.toHexString(fix.offset)).append("\"");
		s.append(" size=\"").print(fix.size);
		s.append("\"");
		s.append(">\n");
		super.saveXml(s);
		s.append("</varnode_sym>\n");
	}

	@Override
	public void saveXmlHeader(PrintStream s)

	{
		s.append("<varnode_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.append("/>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		fix.space = trans.getSpaceByName(el.getAttributeValue("space"));
		fix.offset = XmlUtils.decodeUnknownLong(el.getAttributeValue("offset"));
		fix.size = XmlUtils.decodeUnknownInt(el.getAttributeValue("size"));
		// PatternlessSymbol does not need restoring
	}

}
