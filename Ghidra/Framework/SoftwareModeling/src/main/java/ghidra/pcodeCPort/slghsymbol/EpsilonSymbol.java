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
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

// Another name for zero pattern/value
public class EpsilonSymbol extends PatternlessSymbol {

	private AddrSpace const_space;

	public EpsilonSymbol(Location location) {
		super(location);
	} // For use with restoreXml

	public EpsilonSymbol(Location location, String nm, AddrSpace spc) {
		super(location, nm);
		const_space = spc;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.epsilon_symbol;
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker pos) {
		hand.space = const_space;
		hand.offset_space = null; // Not a dynamic value
		hand.offset_offset = 0;
		hand.size = 0; // Cannot provide size
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		s.append('0');
	}

	@Override
	public VarnodeTpl getVarnode() {
		return new VarnodeTpl(location, new ConstTpl(const_space), new ConstTpl(
			ConstTpl.const_type.real, 0), new ConstTpl(ConstTpl.const_type.real, 0));
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<epsilon_sym");
		saveSleighSymbolXmlHeader(s);
		s.println("/>");
	}

	@Override
	public void saveXmlHeader(PrintStream s) {
		s.append("<epsilon_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.println("/>");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		const_space = trans.getConstantSpace();
	}

}
