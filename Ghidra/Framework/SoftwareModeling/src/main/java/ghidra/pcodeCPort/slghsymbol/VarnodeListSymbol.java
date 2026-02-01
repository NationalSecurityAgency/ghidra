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

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class VarnodeListSymbol extends ValueSymbol {

	private VectorSTL<VarnodeSymbol> varnode_table = new VectorSTL<VarnodeSymbol>();
	private boolean tableisfilled;

	public VarnodeListSymbol(Location location) {
		super(location);
	}

	@Override
	public symbol_type getType() {
		return symbol_type.varnodelist_symbol;
	}

	public VarnodeListSymbol(Location location, String nm, PatternValue pv,
			VectorSTL<SleighSymbol> vt) {
		super(location, nm, pv);
		for (int i = 0; i < vt.size(); ++i) {
			varnode_table.push_back((VarnodeSymbol) vt.get(i));
		}
		checkTableFill();
	}

	private void checkTableFill() {
		long min = patval.minValue();
		long max = patval.maxValue();
		tableisfilled = (min >= 0) && (max < varnode_table.size());
		for (int i = 0; i < varnode_table.size(); ++i) {
			if (varnode_table.get(i) == null) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public int getSize() {
		for (int i = 0; i < varnode_table.size(); ++i) {
			VarnodeSymbol vnsym = varnode_table.get(i); // Assume all are same size
			if (vnsym != null) {
				return vnsym.getSize();
			}
		}
		throw new SleighError("No register attached to: " + getName(), getLocation());
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VARLIST_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		patval.encode(encoder);
		for (int i = 0; i < varnode_table.size(); ++i) {
			if (varnode_table.get(i) == null) {
				encoder.openElement(ELEM_NULL);
				encoder.closeElement(ELEM_NULL);
			}
			else {
				encoder.openElement(ELEM_VAR);
				encoder.writeUnsignedInteger(ATTRIB_ID, varnode_table.get(i).getId());
				encoder.closeElement(ELEM_VAR);
			}
		}
		encoder.closeElement(ELEM_VARLIST_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VARLIST_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_VARLIST_SYM_HEAD);
	}

}
