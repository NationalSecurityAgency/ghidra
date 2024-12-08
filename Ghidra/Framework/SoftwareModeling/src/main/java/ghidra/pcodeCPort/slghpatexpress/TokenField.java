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
import ghidra.pcodeCPort.context.Token;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class TokenField extends PatternValue {

	private Token tok;
	private boolean bigendian;
	private boolean signbit;
	private int bitstart, bitend; // Bits within the token, 0 bit is LEAST signifigant
	private int bytestart, byteend; // Bytes to read to get value
	private int shift; // Amount to shift to align value (bitstart % 8)

	public TokenField(Location location) {
		super(location);
	}

	@Override
	public TokenPattern genMinPattern(VectorSTL<TokenPattern> ops) {
		return new TokenPattern(location, tok);
	}

	@Override
	public long minValue() {
		return 0;
	}

	@Override
	public long maxValue() {
		long res = 0;
		res = ~res;
		res = Utils.zzz_zero_extend(res, bitend - bitstart);
		return res;
	}

	public TokenField(Location location, Token tk, boolean s, int bstart, int bend) {
		super(location);
		tok = tk;
		bigendian = tok.isBigEndian();
		signbit = s;
		bitstart = bstart;
		bitend = bend;
		if (tk.isBigEndian()) {
			byteend = (tk.getSize() * 8 - bitstart - 1) / 8;
			bytestart = (tk.getSize() * 8 - bitend - 1) / 8;
		}
		else {
			bytestart = bitstart / 8;
			byteend = bitend / 8;
		}
		shift = bitstart % 8;
	}

	@Override
	public TokenPattern genPattern(long val) { // Generate corresponding pattern if the
		// value is forced to be val
		return new TokenPattern(location, tok, val, bitstart, bitend);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_TOKENFIELD);
		encoder.writeBool(ATTRIB_BIGENDIAN, bigendian);
		encoder.writeBool(ATTRIB_SIGNBIT, signbit);
		encoder.writeSignedInteger(ATTRIB_STARTBIT, bitstart);
		encoder.writeSignedInteger(ATTRIB_ENDBIT, bitend);
		encoder.writeSignedInteger(ATTRIB_STARTBYTE, bytestart);
		encoder.writeSignedInteger(ATTRIB_ENDBYTE, byteend);
		encoder.writeSignedInteger(ATTRIB_SHIFT, shift);
		encoder.closeElement(ELEM_TOKENFIELD);
	}

}
