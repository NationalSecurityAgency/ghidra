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
package ghidra.pcodeCPort.slghpatexpress;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import generic.stl.VectorSTL;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class ConstantValue extends PatternValue {

	long val;

	public ConstantValue(Location location) {
		super(location);
	}

	public ConstantValue(Location location, long v) {
		super(location);
		val = v;
	}

	@Override
	public TokenPattern genMinPattern(VectorSTL<TokenPattern> ops) {
		return new TokenPattern(location);
	}

	@Override
	public TokenPattern genPattern(long v) {
		return new TokenPattern(location, val == v);
	}

	@Override
	public long minValue() {
		return val;
	}

	@Override
	public long maxValue() {
		return val;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_INTB);
		encoder.writeSignedInteger(ATTRIB_VAL, val);
		encoder.closeElement(ELEM_INTB);
	}

}
