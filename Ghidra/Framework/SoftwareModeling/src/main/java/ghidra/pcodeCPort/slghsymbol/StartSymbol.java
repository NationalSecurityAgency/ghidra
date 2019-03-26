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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.pcodeCPort.context.FixedHandle;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.semantics.ConstTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.StartInstructionValue;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class StartSymbol extends SpecificSymbol {
	private AddrSpace const_space;
	private PatternExpression patexp;

	StartSymbol(Location location) {
		super(location);
		patexp = null;
	} // For use with restoreXml

	@Override
	public PatternExpression getPatternExpression() {
		return patexp;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.start_symbol;
	}

	public StartSymbol(Location location, String nm, AddrSpace cspc) {
		super(location, nm);
		const_space = cspc;
		patexp = new StartInstructionValue(location);
		patexp.layClaim();
	}

	@Override
	public void dispose() {
		if (patexp != null) {
			PatternExpression.release(patexp);
		}
	}

// Returns current instruction offset as a constant
	@Override
	public VarnodeTpl getVarnode() {
		ConstTpl spc = new ConstTpl(const_space);
		ConstTpl off = new ConstTpl(ConstTpl.const_type.j_start);
		ConstTpl sz_zero = new ConstTpl();
		return new VarnodeTpl(location, spc, off, sz_zero);
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker pos) {
		hand.space = pos.getCurSpace();
		hand.offset_space = null;
		hand.offset_offset = pos.getAddr().getOffset(); // Get starting address of instruction
		hand.size = hand.space.getAddrSize();
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		long val = pos.getAddr().getOffset();
		s.append("0x");
		s.print(Long.toHexString(val));
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<start_sym");
		saveSleighSymbolXmlHeader(s);
		s.println("/>");
	}

	@Override
	public void saveXmlHeader(PrintStream s) {
		s.append("<start_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.append("/>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		const_space = trans.getConstantSpace();
		patexp = new StartInstructionValue(null);
		patexp.layClaim();
	}

}
