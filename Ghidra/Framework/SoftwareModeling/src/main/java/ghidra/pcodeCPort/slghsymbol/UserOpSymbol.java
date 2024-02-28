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

import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

// A user-defined pcode-op
public class UserOpSymbol extends SleighSymbol {

	private int index;

	public UserOpSymbol(Location location) {
		super(location);
	}

	public UserOpSymbol(Location location, String nm) {
		super(location, nm);
		index = 0;
	}

	public void setIndex(int ind) {
		index = ind;
	}

	public int getIndex() {
		return index;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.userop_symbol;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_USEROP);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		encoder.writeSignedInteger(ATTRIB_INDEX, index);
		encoder.closeElement(ELEM_USEROP);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_USEROP_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_USEROP_HEAD);
	}

}
