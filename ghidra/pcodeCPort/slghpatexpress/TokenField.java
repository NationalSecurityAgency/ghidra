/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.context.Token;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class TokenField extends PatternValue {

	private Token tok;
	private boolean bigendian;
	private boolean signbit;
	private int bitstart, bitend; // Bits within the token, 0 bit is LEAST signifigant
	private int bytestart, byteend; // Bytes to read to get value
	private int shift; // Amount to shift to align value (bitstart % 8)

	public TokenField(Location location) {
		super(location);
	} // For use with restoreXml

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
	public long getValue(ParserWalker pos) { // Construct value given specific
												// instruction stream
		long res = ExpressUtils.getInstructionBytes(pos, bytestart, byteend, bigendian);

		res >>>= shift;
		if (signbit) {
			res = Utils.zzz_sign_extend(res, bitend - bitstart);
		}
		else {
			res = Utils.zzz_zero_extend(res, bitend - bitstart);
		}
		return res;
	}

	@Override
	public TokenPattern genPattern(long val) { // Generate corresponding pattern if the
		// value is forced to be val
		return new TokenPattern(location, tok, val, bitstart, bitend);
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<tokenfield");
		s.append(" bigendian=\"");
		if (bigendian) {
			s.append("true\"");
		}
		else {
			s.append("false\"");
		}
		s.append(" signbit=\"");
		if (signbit) {
			s.append("true\"");
		}
		else {
			s.append("false\"");
		}
		s.append(" bitstart=\"").print(bitstart);
		s.append("\"");
		s.append(" bitend=\"").print(bitend);
		s.append("\"");
		s.append(" bytestart=\"").print(bytestart);
		s.append("\"");
		s.append(" byteend=\"").print(byteend);
		s.append("\"");
		s.append(" shift=\"").print(shift);
		s.append("\"/>\n");
	}

	@Override
	public void restoreXml(Element el, Translate trans) {
		tok = null;
		bigendian = XmlUtils.decodeBoolean(el.getAttributeValue("bigendian"));
		signbit = XmlUtils.decodeBoolean(el.getAttributeValue("signbit"));
		bitstart = XmlUtils.decodeUnknownInt(el.getAttributeValue("bitstart"));
		bitend = XmlUtils.decodeUnknownInt(el.getAttributeValue("bitend"));
		bytestart = XmlUtils.decodeUnknownInt(el.getAttributeValue("bytestart"));
		byteend = XmlUtils.decodeUnknownInt(el.getAttributeValue("byteend"));
		shift = XmlUtils.decodeUnknownInt(el.getAttributeValue("shift"));
	}

}
