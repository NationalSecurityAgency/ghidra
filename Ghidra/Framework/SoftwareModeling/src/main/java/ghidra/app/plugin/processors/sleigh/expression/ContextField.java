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
/*
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.expression;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Contiguous bits in the non-instruction part of the context interpreted
 * as an integer value
 */
public class ContextField extends PatternValue {

	private int startbit, endbit;
	private int startbyte, endbyte;
	private int shift;
	private boolean signbit;

	@Override
	public int hashCode() {
		int result = 0;
		result += startbit;
		result *= 31;
		result += endbit;
		// NOTE: start/end byte and shift are subsumed by bits
		result *= 31;
		result += Boolean.hashCode(signbit);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ContextField)) {
			return false;
		}
		ContextField that = (ContextField) obj;
		if (this.startbit != that.startbit) {
			return false;
		}
		if (this.endbit != that.endbit) {
			return false;
		}
		if (this.signbit != that.signbit) {
			return false;
		}
		return true;
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

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.expression.PatternValue#minValue()
	 */
	@Override
	public long minValue() {
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.expression.PatternValue#maxValue()
	 */
	@Override
	public long maxValue() {
		long res = -1;
		res <<= (endbit - startbit);
		res <<= 1;
		return ~res;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PatternExpression#getValue(ghidra.app.plugin.processors.sleigh.InstructionContext)
	 */
	@Override
	public long getValue(ParserWalker walker) throws MemoryAccessException {
		long res = getContextBytes(walker);
		res >>= shift;
		if (signbit)
			res = TokenField.signExtend(res, endbit - startbit);
		else
			res = TokenField.zeroExtend(res, endbit - startbit);
		return res;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PatternExpression#restoreXml(org.jdom.Element)
	 */
	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.start("contextfield");
		signbit = SpecXmlUtils.decodeBoolean(el.getAttribute("signbit"));
		startbit = SpecXmlUtils.decodeInt(el.getAttribute("startbit"));
		endbit = SpecXmlUtils.decodeInt(el.getAttribute("endbit"));
		startbyte = SpecXmlUtils.decodeInt(el.getAttribute("startbyte"));
		endbyte = SpecXmlUtils.decodeInt(el.getAttribute("endbyte"));
		shift = SpecXmlUtils.decodeInt(el.getAttribute("shift"));
		parser.end(el);
	}

	/**
	 * Build a long from the context bytes in pos
	 * @param pos
	 * @return
	 */
	private long getContextBytes(ParserWalker walker) {
		long res = 0;
		int tmp;
		int size;
		int bs = startbyte;

		size = endbyte - bs + 1;
		while (size >= 4) {
			tmp = walker.getContextBytes(bs, 4);
			res <<= 32;
			res |= tmp;
			bs += 4;
			size = endbyte - bs + 1;
		}
		if (size > 0) {
			tmp = walker.getContextBytes(bs, size);
			res <<= 8 * size;
			res |= tmp;
		}
		return res;
	}

	public boolean hasSignbit() {
		return signbit;
	}

	public int getByteStart() {
		return startbyte;
	}

	public int getByteEnd() {
		return endbyte;
	}

	public int getShift() {
		return shift;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("[ctx(" + startbit + "," + endbit + ")");
		if (signbit) {
			sb.append(", signed");
		}
		sb.append(", bytes " + startbyte + "-" + endbyte);
		sb.append(", shift=" + shift);
		sb.append("]");
		return sb.toString();
	}
}
