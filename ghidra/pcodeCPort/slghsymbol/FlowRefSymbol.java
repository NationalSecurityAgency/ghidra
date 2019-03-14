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

import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.context.FixedHandle;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.semantics.ConstTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.sleigh.grammar.Location;

/**
 * Symbol with semantic value equal to reference address at the injection site
 * NOTE: only useable for pcode snippets
 */
public class FlowRefSymbol extends SpecificSymbol {
	private AddrSpace const_space;
	
	public FlowRefSymbol(Location location, String nm, AddrSpace cspc) {
		super(location, nm);
		const_space = cspc;
//		patexp = new StartInstructionValue(location);
//		patexp.layClaim();
	}

	@Override
    public PatternExpression getPatternExpression() {
		return null;		// Cannot be used in pattern expressions
	}

	@Override
	public symbol_type getType() {
		return symbol_type.start_symbol;
	}

	@Override
    public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		Address refAddr = walker.getFlowRefAddr();
		hand.space = const_space;
		hand.offset_space = null;
		hand.offset_offset = refAddr.getOffset();
		hand.size = refAddr.getAddrSize();
	}

	@Override
	public VarnodeTpl getVarnode() {
		ConstTpl spc = new ConstTpl(const_space);
		ConstTpl off = new ConstTpl(ConstTpl.const_type.j_flowref);
		ConstTpl sz_zero = new ConstTpl();
		return new VarnodeTpl(location, spc, off, sz_zero);
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		long val = pos.getFlowRefAddr().getOffset();
		s.append("0x");
		s.print(Long.toHexString(val));
	}
}
