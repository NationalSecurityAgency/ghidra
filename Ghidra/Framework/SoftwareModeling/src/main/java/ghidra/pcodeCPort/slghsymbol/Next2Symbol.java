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

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import ghidra.pcodeCPort.semantics.ConstTpl;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.slghpatexpress.Next2InstructionValue;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class Next2Symbol extends SpecificSymbol {
	private AddrSpace const_space;
	private PatternExpression patexp;

	public Next2Symbol(Location location) {
		super(location);
		patexp = null;
	}

	@Override
	public PatternExpression getPatternExpression() {
		return patexp;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.next2_symbol;
	}

	public Next2Symbol(Location location, String nm, AddrSpace cspc) {
		super(location, nm);
		const_space = cspc;
		patexp = new Next2InstructionValue(location);
		patexp.layClaim();
	}

	@Override
	public void dispose() {
		if (patexp != null) {
			PatternExpression.release(patexp);
		}
	}

// Return next instruction offset as a constant
	@Override
	public VarnodeTpl getVarnode() {
		ConstTpl spc = new ConstTpl(const_space);
		ConstTpl off = new ConstTpl(ConstTpl.const_type.j_next2);
		ConstTpl sz_zero = new ConstTpl();
		return new VarnodeTpl(location, spc, off, sz_zero);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_NEXT2_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		encoder.closeElement(ELEM_NEXT2_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_NEXT2_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_NEXT2_SYM_HEAD);
	}

}
