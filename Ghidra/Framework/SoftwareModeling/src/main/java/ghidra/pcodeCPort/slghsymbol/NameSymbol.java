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

public class NameSymbol extends ValueSymbol {

	private VectorSTL<String> nametable = new VectorSTL<>();
	private boolean tableisfilled;

	public NameSymbol(Location location) {
		super(location);
	}

	public NameSymbol(Location location, String nm, PatternValue pv, VectorSTL<String> nt) {
		super(location, nm, pv);
		nametable = nt;
		checkTableFill();
	}

	private void checkTableFill() {
		// Check if all possible entries in the table have been filled
		long min = patval.minValue();
		long max = patval.maxValue();
		tableisfilled = (min >= 0) && (max < nametable.size());
		for (int i = 0; i < nametable.size(); ++i) {
			if (nametable.get(i) == null) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public symbol_type getType() {
		return symbol_type.name_symbol;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_NAME_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		patval.encode(encoder);
		for (int i = 0; i < nametable.size(); ++i) {
			String name = nametable.get(i);
			encoder.openElement(ELEM_NAMETAB);
			if (name != null) {
				encoder.writeString(ATTRIB_NAME, name);
			}
			encoder.closeElement(ELEM_NAMETAB);
		}
		encoder.closeElement(ELEM_NAME_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_NAME_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_NAME_SYM_HEAD);
	}

}
