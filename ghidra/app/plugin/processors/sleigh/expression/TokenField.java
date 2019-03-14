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
 * A contiguous set of bits within instruction stream, interpreted
 * as an integer value
 */
public class TokenField extends PatternValue {

	private boolean bigendian;
	private boolean signbit;
	private int bitstart, bitend;	// Bits within token, 0 bit is LEAST sig
	private int bytestart, byteend;	// Bytes to read to get value
	private int shift;				// Amount to shift to align value

	@Override
	public int hashCode() {
		int result = 0;
		result += bitstart;
		result *= 31;
		result += bitend;
		// NOTE: start/end byte and shift are subsumed by bits
		result *= 31;
		result += Boolean.hashCode(signbit);
		result *= 31;
		result += Boolean.hashCode(bigendian);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof TokenField)) {
			return false;
		}
		TokenField that = (TokenField) obj;
		if (this.bitstart != that.bitstart) {
			return false;
		}
		if (this.bitend != that.bitend) {
			return false;
		}
		if (this.signbit != that.signbit) {
			return false;
		}
		if (this.bigendian != that.bigendian) {
			return false;
		}
		return true;
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
		res <<= (bitend - bitstart);
		res <<= 1;
		return ~res;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PatternExpression#getValue(ghidra.app.plugin.processors.sleigh.InstructionContext)
	 */
	@Override
	public long getValue(ParserWalker walker) throws MemoryAccessException {
		long res = getInstructionBytes(walker);

		res >>= shift;
		if (signbit)
			res = signExtend(res, bitend - bitstart);
		else
			res = zeroExtend(res, bitend - bitstart);
		return res;
	}

	public int getBitStart() {
		return bitstart;
	}

	public int getBitEnd() {
		return bitend;
	}

	public int getByteStart() {
		return bytestart;
	}

	public int getByteEnd() {
		return byteend;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PatternExpression#restoreXml(org.jdom.Element)
	 */
	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.start("tokenfield");
		bigendian = SpecXmlUtils.decodeBoolean(el.getAttribute("bigendian"));
		signbit = SpecXmlUtils.decodeBoolean(el.getAttribute("signbit"));
		bitstart = SpecXmlUtils.decodeInt(el.getAttribute("bitstart"));
		bitend = SpecXmlUtils.decodeInt(el.getAttribute("bitend"));
		bytestart = SpecXmlUtils.decodeInt(el.getAttribute("bytestart"));
		byteend = SpecXmlUtils.decodeInt(el.getAttribute("byteend"));
		shift = SpecXmlUtils.decodeInt(el.getAttribute("shift"));
		parser.end(el);
	}

	public boolean hasSignbit() {
		return signbit;
	}

	/**
	 * Build a long from the instruction bytes in pos
	 * @param pos      Current instruction
	 * @return
	 * @throws MemoryAccessException
	 */
	private long getInstructionBytes(ParserWalker walker) throws MemoryAccessException {
		long res = 0;
		long tmp;
		int size, tmpsize;
		int bs = bytestart;

		size = byteend - bytestart + 1;
		tmpsize = size;
		while (tmpsize >= 4) {
			tmp = walker.getInstructionBytes(bs, 4);
			res = res << 32;
			res |= (tmp & 0xffffffffl);
			bs += 4;
			tmpsize -= 4;
		}
		if (tmpsize > 0) {
			tmp = walker.getInstructionBytes(bs, tmpsize);
			res = res << (8 * tmpsize);
			res |= (tmp & 0xffffffffl);
		}
		if (!bigendian)
			res = byteSwap(res, size);
		return res;
	}

	/**
	 * Sign extend -val- above -bit-
	 * @param val     value to extend
	 * @param bit     bit specifying sign
	 * @return
	 */
	public static long signExtend(long val, int bit) {
		long mask = 0;
		mask = (~mask) << bit;
		if (((val >> bit) & 1) != 0)
			val |= mask;
		else
			val &= (~mask);
		return val;
	}

	/**
	 * Clear all bits in -val- above -bit-
	 * @param val   value to zero extend
	 * @param bit   bit above which to zero extend
	 * @return
	 */
	public static long zeroExtend(long val, int bit) {
		long mask = 0;
		mask = (~mask) << bit;
		mask <<= 1;
		val &= (~mask);
		return val;
	}

	/**
	 * Swap the least sig -size- bytes in -val-
	 * @param val    value to be byte swapped
	 * @param size   number of bytes involved in swap
	 * @return
	 */
	public static long byteSwap(long val, int size) {
		long res = 0;
		while (size > 0) {
			res <<= 8;
			res |= (val & 0xff);
			val >>= 8;
			size -= 1;
		}
		return res;
	}

	public boolean isBigEndian() {
		return bigendian;
	}

	public int getShift() {
		return shift;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("[ins(" + bitstart + "," + bitend + ")");
		if (signbit) {
			sb.append(", signed");
		}
		if (bigendian) {
			sb.append(", bigendian");
		}
		sb.append(", bytes " + bytestart + "-" + byteend);
		sb.append(", shift=" + shift);
		sb.append("]");
		return sb.toString();
	}
}
