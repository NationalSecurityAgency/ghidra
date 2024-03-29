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

import ghidra.pcodeCPort.semantics.ConstTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.sleigh.grammar.Location;

/**
 * Symbol with semantic value equal to the original
 * primary call destination address.
 * NOTE: only useable for pcode snippets
 */
public class FlowDestSymbol extends SpecificSymbol {
	private AddrSpace const_space;

	public FlowDestSymbol(Location location, String nm, AddrSpace cspc) {
		super(location, nm);
		const_space = cspc;
	}

	@Override
	public PatternExpression getPatternExpression() {
		return null; // Cannot be used in pattern expressions
	}

	@Override
	public symbol_type getType() {
		return symbol_type.flowdest_symbol;
	}

	@Override
	public VarnodeTpl getVarnode() {
		ConstTpl spc = new ConstTpl(const_space);
		ConstTpl off = new ConstTpl(ConstTpl.const_type.j_flowdest);
		ConstTpl sz_zero = new ConstTpl();
		return new VarnodeTpl(location, spc, off, sz_zero);
	}

}
