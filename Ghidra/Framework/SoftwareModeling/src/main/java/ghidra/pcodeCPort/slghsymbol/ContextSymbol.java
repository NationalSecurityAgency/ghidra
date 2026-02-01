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

import ghidra.pcodeCPort.slghpatexpress.ContextField;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class ContextSymbol extends ValueSymbol {

	private VarnodeSymbol vn;
	private int low, high; // into a varnode
	private boolean flow;

	public ContextSymbol(Location location) {
		super(location);
	}

	public VarnodeSymbol getVarnode() {
		return vn;
	}

	public int getLow() {
		return low;
	}

	public int getHigh() {
		return high;
	}

	public boolean isFlow() {
		return flow;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.context_symbol;
	}

	public ContextSymbol(Location location, String nm, ContextField pate, VarnodeSymbol v, int l,
			int h, boolean flow) {
		super(location, nm, pate);
		vn = v;
		low = l;
		high = h;
		this.flow = flow;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONTEXT_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		encoder.writeUnsignedInteger(ATTRIB_VARNODE, vn.getId());
		encoder.writeSignedInteger(ATTRIB_LOW, low);
		encoder.writeSignedInteger(ATTRIB_HIGH, high);
		encoder.writeBool(ATTRIB_FLOW, flow);
		patval.encode(encoder);
		encoder.closeElement(ELEM_CONTEXT_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONTEXT_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_CONTEXT_SYM_HEAD);
	}

}
