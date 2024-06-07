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
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

// Another name for zero pattern/value
public class EpsilonSymbol extends PatternlessSymbol {

	private AddrSpace const_space;

	public EpsilonSymbol(Location location) {
		super(location);
	}

	public EpsilonSymbol(Location location, String nm, AddrSpace spc) {
		super(location, nm);
		const_space = spc;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.epsilon_symbol;
	}

	@Override
	public VarnodeTpl getVarnode() {
		return new VarnodeTpl(location, new ConstTpl(const_space),
			new ConstTpl(ConstTpl.const_type.real, 0), new ConstTpl(ConstTpl.const_type.real, 0));
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_EPSILON_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		encoder.closeElement(ELEM_EPSILON_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_EPSILON_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_EPSILON_SYM_HEAD);
	}

}
