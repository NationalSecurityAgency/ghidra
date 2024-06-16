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
import ghidra.pcodeCPort.utils.Utils;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class ContextField extends PatternValue {

	private int startbit, endbit;
	private int startbyte, endbyte;
	private int shift;
	private boolean signbit;

	public ContextField(Location location) {
		super(location);
	}

	public int getStartBit() {
		return startbit;
	}

	public int getEndBit() {
		return endbit;
	}

	public boolean getSignBit() {
		return signbit;
	}

	@Override
	public TokenPattern genMinPattern(VectorSTL<TokenPattern> ops) {
		return new TokenPattern(location);
	}

	@Override
	public long minValue() {
		return 0;
	}

	@Override
	public long maxValue() {
		long res = 0;
		res = ~res;
		res = Utils.zzz_zero_extend(res, (endbit - startbit));
		return res;
	}

	public ContextField(Location location, boolean s, int sbit, int ebit)

	{
		super(location);
		signbit = s;
		startbit = sbit;
		endbit = ebit;
		startbyte = startbit / 8;
		endbyte = endbit / 8;
		shift = 7 - (endbit % 8);
	}

	@Override
	public String toString() {
		return "cf:{" + startbit + "," + endbit + "," + startbyte + "," + endbyte + "," + shift +
			"," + signbit + "}";
	}

	@Override
	public TokenPattern genPattern(long val) {
		return new TokenPattern(location, val, startbit, endbit);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONTEXTFIELD);
		encoder.writeBool(ATTRIB_SIGNBIT, signbit);
		encoder.writeSignedInteger(ATTRIB_STARTBIT, startbit);
		encoder.writeSignedInteger(ATTRIB_ENDBIT, endbit);
		encoder.writeSignedInteger(ATTRIB_STARTBYTE, startbyte);
		encoder.writeSignedInteger(ATTRIB_ENDBYTE, endbyte);
		encoder.writeSignedInteger(ATTRIB_SHIFT, shift);
		encoder.closeElement(ELEM_CONTEXTFIELD);
	}

}
