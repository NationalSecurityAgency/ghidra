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
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class ValueMapSymbol extends ValueSymbol {
	private VectorSTL<Long> valuetable = new VectorSTL<Long>();
	private boolean tableisfilled;

	public ValueMapSymbol(Location location) {
		super(location);
	}

	public ValueMapSymbol(Location location, String nm, PatternValue pv, VectorSTL<Long> vt) {
		super(location, nm, pv);
		valuetable = new VectorSTL<Long>(vt);
		checkTableFill();
	}

	@Override
	public symbol_type getType() {
		return symbol_type.valuemap_symbol;
	}

	private void checkTableFill() {
		// Check if all possible entries in the table have been filled
		long min = patval.minValue();
		long max = patval.maxValue();
		tableisfilled = (min >= 0) && (max < valuetable.size());
		for (int i = 0; i < valuetable.size(); ++i) {
			if (valuetable.get(i) == 0xBADBEEF) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VALUEMAP_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		patval.encode(encoder);
		for (int i = 0; i < valuetable.size(); ++i) {
			encoder.openElement(ELEM_VALUETAB);
			encoder.writeSignedInteger(ATTRIB_VAL, valuetable.get(i));
			encoder.closeElement(ELEM_VALUETAB);
		}
		encoder.closeElement(ELEM_VALUEMAP_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VALUEMAP_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_VALUEMAP_SYM_HEAD);
	}

}
