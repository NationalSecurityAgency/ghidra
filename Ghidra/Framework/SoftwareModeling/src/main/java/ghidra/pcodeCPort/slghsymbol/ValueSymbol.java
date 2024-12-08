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

import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class ValueSymbol extends FamilySymbol {

	protected PatternValue patval;

	public ValueSymbol(Location location) {
		super(location);
		patval = null;
	}

	public ValueSymbol(Location location, String nm, PatternValue pv) {
		super(location, nm);
		patval = pv;
		patval.layClaim();
	}

	@Override
	public PatternValue getPatternValue() {
		return patval;
	}

	@Override
	public PatternExpression getPatternExpression() {
		return patval;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.value_symbol;
	}

	@Override
	public void dispose() {
		if (patval != null) {
			PatternExpression.release(patval);
		}
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VALUE_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		patval.encode(encoder);
		encoder.closeElement(ELEM_VALUE_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException

	{
		encoder.openElement(ELEM_VALUE_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_VALUE_SYM_HEAD);
	}

}
