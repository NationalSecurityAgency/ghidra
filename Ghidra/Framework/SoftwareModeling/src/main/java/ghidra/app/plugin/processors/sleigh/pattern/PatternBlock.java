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
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.pattern;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.NumericUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A mask/value pair viewed as two bitstreams
 */
public class PatternBlock {
	int offset;					// Offset first to non-zero byte of mask
	int nonzerosize;			// Last byte(+1) containing nonzero mask
	int[] maskvec;				// mask
	int[] valvec;				// value

	private static int[] eraseArray(int[] array, int start, int end) {
		int delsize = end - start;
		int newsize = array.length - delsize;
		int[] res = new int[newsize];
		for (int i = 0; i < start; ++i)
			res[i] = array[i];
		for (int i = end; i < array.length; ++i)
			res[i - delsize] = array[i];
		return res;
	}

	public int[] getMaskVector() {
		return maskvec;
	}

	public int[] getValueVector() {
		return valvec;
	}

	private void normalize() {
		if (nonzerosize <= 0) {	// Check if alwaystrue or alwaysfalse
			offset = 0;
			maskvec = null;
			valvec = null;
			return;
		}
		int iter1 = 0;
		int iter2 = 0;		// Cut zeros from beginning of mask
		while ((iter1 != maskvec.length) && (maskvec[iter1] == 0)) {
			iter1++;
			iter2++;
			offset += 4;	// Sizeof int
		}
		maskvec = eraseArray(maskvec, 0, iter1);
		valvec = eraseArray(valvec, 0, iter2);

		if (maskvec.length != 0) {
			int suboff = 0;		// Cut off unaligned zeros from beginning
			int tmp = maskvec[0];
			while (tmp != 0) {
				suboff += 1;
				tmp >>>= 8;
			}
			suboff = 4 - suboff;
			if (suboff != 0) {
				offset += suboff;	// Slide up maskvec by suboff bytes
				for (int i = 0; i < maskvec.length - 1; ++i) {
					tmp = maskvec[i] << (suboff * 8);
					tmp |= (maskvec[i + 1] >>> ((4 - suboff) * 8));
					maskvec[i] = tmp;
				}
				maskvec[maskvec.length - 1] <<= suboff * 8;
				for (int i = 0; i < valvec.length - 1; ++i) {	// Slide up valvec
					tmp = valvec[i] << (suboff * 8);
					tmp |= (valvec[i] >>> ((4 - suboff) * 8));
					valvec[i] = tmp;
				}
				valvec[valvec.length - 1] <<= suboff * 8;
			}

			iter1 = maskvec.length;		// Cut zeros from end of mask
			iter2 = valvec.length;
			while (iter1 != 0) {
				--iter1;
				--iter2;
				if (maskvec[iter1] != 0)
					break;	// Find last non-zero
			}
			if (iter1 != maskvec.length) {
				iter1++;			// Find first zero,in last zero chain
				iter2++;
			}
			maskvec = eraseArray(maskvec, iter1, maskvec.length);
			valvec = eraseArray(valvec, iter2, valvec.length);
		}

		if (maskvec.length == 0) {
			offset = 0;
			nonzerosize = 0;	// Always true
			maskvec = null;
			valvec = null;
			return;
		}
		nonzerosize = maskvec.length * 4;
		int tmp = maskvec[maskvec.length - 1];	// tmp must be nonzero
		while ((tmp & 0xff) == 0) {
			nonzerosize -= 1;
			tmp >>>= 8;
		}
	}

	public PatternBlock(int off, int msk, int val) {
		offset = off;
		maskvec = new int[1];
		maskvec[0] = msk;
		valvec = new int[1];
		valvec[0] = val;
		nonzerosize = 4;	// Assume all non-zero bytes before normalization
		normalize();
	}

	public PatternBlock(boolean tf) {
		offset = 0;
		if (tf)
			nonzerosize = 0;
		else
			nonzerosize = -1;
		maskvec = null;
		valvec = null;
	}

	public PatternBlock(PatternBlock a, PatternBlock b) {
		PatternBlock res = a.andBlock(b);
		offset = res.offset;
		nonzerosize = res.nonzerosize;
		maskvec = res.maskvec.clone();
		valvec = res.valvec.clone();
	}

	public PatternBlock(ArrayList<?> list) {
		PatternBlock res;

		if (list.size() == 0) {
			offset = 0;
			nonzerosize = 0;
			maskvec = null;
			valvec = null;
			return;
		}
		res = (PatternBlock) list.get(0);
		for (int i = 1; i < list.size(); ++i) {
			res = res.andBlock((PatternBlock) list.get(i));
		}
		offset = res.offset;
		nonzerosize = res.nonzerosize;
		maskvec = res.maskvec.clone();
		valvec = res.valvec.clone();
	}

	@Override
	public Object clone() {
		PatternBlock res = new PatternBlock(true);
		res.offset = offset;
		res.nonzerosize = nonzerosize;
		res.maskvec = maskvec.clone();
		res.valvec = valvec.clone();
		return res;
	}

	public PatternBlock andBlock(PatternBlock b) {
		PatternBlock res = new PatternBlock(true);
		int maxlength = (getLength() > b.getLength()) ? getLength() : b.getLength();

		int asize = maxlength / 4;
		if (maxlength % 4 != 0)
			asize += 1;
		res.maskvec = new int[asize];
		res.valvec = new int[asize];
		res.offset = 0;
		int offset1 = 0;
		int i = 0;
		int mask1, val1, mask2, val2;
		while (offset1 < maxlength) {
			mask1 = getMask(offset1 * 8, 32);
			val1 = getValue(offset1 * 8, 32);
			mask2 = b.getMask(offset1 * 8, 32);
			val2 = b.getValue(offset1 * 8, 32);
			if (((mask2 & mask1) & val2) != ((mask2 & mask1) & val1))
				break;	// Impossible pattern
			res.maskvec[i] = mask1 | mask2;
			res.valvec[i] = val1 | val2;
			offset1 += 4;
			i += 1;
		}
		if (offset1 < maxlength)		// If pattern is impossible
			res.nonzerosize = -1;
		else
			res.nonzerosize = maxlength;
		res.normalize();
		return res;
	}

	public boolean specializes(PatternBlock op2) {
		int length = 8 * op2.getLength();
		int tmplength;
		int mask1, mask2, value1, value2;
		int sbit = 0;
		while (sbit < length) {
			tmplength = length - sbit;
			if (tmplength > 32)
				tmplength = 32;
			mask1 = getMask(sbit, tmplength);
			value1 = getValue(sbit, tmplength);
			mask2 = op2.getMask(sbit, tmplength);
			value2 = op2.getValue(sbit, tmplength);
			if ((mask1 & mask2) != mask2)
				return false;
			if ((value1 & mask2) != (value2 & mask2))
				return false;
			sbit += tmplength;
		}
		return true;
	}

	public boolean identical(PatternBlock op2) {
		int length = 8 * op2.getLength();
		int tmplength;
		int mask1, mask2, value1, value2;
		int sbit = 0;
		while (sbit < length) {
			tmplength = length - sbit;
			if (tmplength > 32)
				tmplength = 32;
			mask1 = getMask(sbit, tmplength);
			value1 = getValue(sbit, tmplength);
			mask2 = op2.getMask(sbit, tmplength);
			value2 = op2.getValue(sbit, tmplength);
			if (mask1 != mask2)
				return false;
			if ((mask1 & value1) != (mask2 & value2))
				return false;
			sbit += tmplength;
		}
		return true;
	}

	public void shift(int sa) {
		offset += sa;
		normalize();
	}

	public int getLength() {
		return offset + nonzerosize;
	}

	public int getMask(int startbit, int size) {
		startbit -= 8 * offset;
		int wordnum1 = startbit / 32;
		int shift = startbit % 32;
		int wordnum2 = (startbit + size - 1) / 32;
		int res;

		if ((wordnum1 < 0) || (wordnum1 >= maskvec.length))
			res = 0;
		else
			res = maskvec[wordnum1];
		res <<= shift;
		if (wordnum1 != wordnum2) {
			int tmp;
			if ((wordnum2 < 0) || (wordnum2 >= maskvec.length))
				tmp = 0;
			else
				tmp = maskvec[wordnum2];
			res |= (tmp >>> (32 - shift));
		}
		res >>>= 32 - size;
		return res;
	}

	public int getValue(int startbit, int size) {
		startbit -= 8 * offset;
		int wordnum1 = startbit / 32;
		int shift = startbit % 32;
		int wordnum2 = (startbit + size - 1) / 32;
		int res;

		if ((wordnum1 < 0) || (wordnum1 >= valvec.length))
			res = 0;
		else
			res = valvec[wordnum1];
		res <<= shift;
		if (wordnum1 != wordnum2) {
			int tmp;
			if ((wordnum2 < 0) || (wordnum2 >= valvec.length))
				tmp = 0;
			else
				tmp = valvec[wordnum2];
			res |= (tmp >>> (32 - shift));
		}
		res >>>= 32 - size;
		return res;
	}

	public boolean alwaysTrue() {
		return (nonzerosize == 0);
	}

	public boolean alwaysFalse() {
		return (nonzerosize == -1);
	}

	public boolean isInstructionMatch(ParserWalker walker) {
		if (nonzerosize <= 0)
			return (nonzerosize == 0);
		int off = offset;
		try {
			for (int i = 0; i < maskvec.length; ++i) {
				int data = walker.getInstructionBytes(off, 4);
				if ((maskvec[i] & data) != valvec[i])
					return false;
				off += 4;
			}
			return true;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	public boolean isContextMatch(ParserWalker walker) {
		if (nonzerosize <= 0)
			return (nonzerosize == 0);
		int off = offset;
		for (int i = 0; i < maskvec.length; ++i) {
			int data = walker.getContextBytes(off, 4);
			if ((maskvec[i] & data) != valvec[i])
				return false;
			off += 4;
		}
		return true;
	}

	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("pat_block");
		offset = SpecXmlUtils.decodeInt(el.getAttribute("offset"));
		nonzerosize = SpecXmlUtils.decodeInt(el.getAttribute("nonzero"));
		ArrayList<String> masks = new ArrayList<>();
		ArrayList<String> vals = new ArrayList<>();
		XmlElement subel;
		while ((subel = parser.softStart("mask_word")) != null) {
			masks.add(subel.getAttribute("mask"));
			vals.add(subel.getAttribute("val"));
			parser.end(subel);
		}
		maskvec = new int[masks.size()];
		valvec = new int[vals.size()];
		for (int i = 0; i < maskvec.length; ++i) {
			maskvec[i] = SpecXmlUtils.decodeInt(masks.get(i));
			valvec[i] = SpecXmlUtils.decodeInt(vals.get(i));
		}
		parser.end(el);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < offset; i++) {
			sb.append("SS:");
		}
		for (int i = 0; i < maskvec.length; i++) {
			if (i != 0) {
				sb.append(':');
			}
			sb.append(NumericUtilities.convertMaskedValueToHexString(maskvec[i], valvec[i], 8,
				false, 2, ":"));
		}
		if (sb.length() == 0) {
			return "[]";
		}
		return sb.toString();
	}

	public int getOffset() {
		return offset;
	}

	public int getNonZeroLength() {
		return nonzerosize;
	}

	protected static final int SHAMT = 24;
	protected static final int LEFT_BYTE = 0xff << SHAMT;

	/**
	 * Extract those portions of the pattern which constitute fully-specified bytes
	 * @return an array of bytes
	 */
	public byte[] getWholeBytes() {
		int count = 0;
		for (int i = 0; i < maskvec.length; i++) {
			int mask = maskvec[i];
			for (int j = 0; j < 4; j++) {
				if ((mask & LEFT_BYTE) == LEFT_BYTE) {
					count++;
				}
				mask <<= 8;
			}
		}
		byte[] result = new byte[count];
		int pos = 0;
		for (int i = 0; i < maskvec.length; i++) {
			int mask = maskvec[i];
			int valu = valvec[i];
			for (int j = 0; j < 4; j++) {
				if ((mask & LEFT_BYTE) == LEFT_BYTE) {
					result[pos++] = (byte) ((valu & LEFT_BYTE) >>> SHAMT);
				}
				mask <<= 8;
				valu <<= 8;
			}
		}
		return result;
	}
}
