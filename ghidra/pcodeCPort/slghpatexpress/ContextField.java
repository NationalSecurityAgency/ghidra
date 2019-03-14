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
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class ContextField extends PatternValue {

	private int startbit, endbit;
	private int startbyte, endbyte;
	private int shift;
	private boolean signbit;

	public ContextField(Location location) {
		super(location);
	} // For use with restoreXml

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
	public long getValue(ParserWalker pos) {
		long res = ExpressUtils.getContextBytes(pos, startbyte, endbyte);
		res >>>= shift;
		if (signbit) {
			res = Utils.zzz_sign_extend(res, endbit - startbit);
		}
		else {
			res = Utils.zzz_zero_extend(res, endbit - startbit);
		}
		return res;
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
	public void saveXml(PrintStream s) {
		s.append("<contextfield");
		s.append(" signbit=\"");
		if (signbit) {
			s.append("true\"");
		}
		else {
			s.append("false\"");
		}
		s.append(" startbit=\"");
		s.print(startbit);
		s.append("\"");
		s.append(" endbit=\"");
		s.print(endbit);
		s.append("\"");
		s.append(" startbyte=\"").print(startbyte);
		s.append("\"");
		s.append(" endbyte=\"").print(endbyte);
		s.append("\"");
		s.append(" shift=\"").print(shift);
		s.append("\"/>\n");
	}

	@Override
	public void restoreXml(Element el, Translate trans) {
		signbit = XmlUtils.decodeBoolean(el.getAttributeValue("signbit"));
		startbit = XmlUtils.decodeUnknownInt(el.getAttributeValue("startbit"));
		endbit = XmlUtils.decodeUnknownInt(el.getAttributeValue("endbit"));
		startbyte = XmlUtils.decodeUnknownInt(el.getAttributeValue("startbyte"));
		endbyte = XmlUtils.decodeUnknownInt(el.getAttributeValue("endbyte"));
		shift = XmlUtils.decodeUnknownInt(el.getAttributeValue("shift"));
	}

}
