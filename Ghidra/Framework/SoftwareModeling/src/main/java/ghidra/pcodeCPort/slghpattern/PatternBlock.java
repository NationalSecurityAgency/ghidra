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
package ghidra.pcodeCPort.slghpattern;

import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.pcodeCPort.utils.XmlUtils;

public class PatternBlock {

	int offset; // Offset to non-zero byte of mask
	int nonzerosize; // Last byte(+1) containing nonzero mask
	VectorSTL<Integer> maskvec = new VectorSTL<>(); // Mask
	VectorSTL<Integer> valvec = new VectorSTL<>(); // Value

	public void shift(int sa) {
		offset += sa;
		normalize();
	}

	public int getLength() {
		return offset + nonzerosize;
	}

	public boolean alwaysTrue() {
		return (nonzerosize == 0);
	}

	public boolean alwaysFalse() {
		return (nonzerosize == -1);
	}

	public void dispose() {

	}

	private void normalize() {
		if (nonzerosize <= 0) { // Check if alwaystrue or alwaysfalse
			offset = 0; // in which case we don't need mask and value
			maskvec.clear();
			valvec.clear();
			return;
		}
		IteratorSTL<Integer> iter1 = maskvec.begin(); // Cut zeros from beginning of mask
		IteratorSTL<Integer> iter2 = valvec.begin();
		while (!iter1.isEnd() && (iter1.get() == 0)) {
			iter1.increment();
			iter2.increment();
			offset += 4; // sizeof Integer
		}
		maskvec.erase(maskvec.begin(), iter1);
		valvec.erase(valvec.begin(), iter2);

		if (!maskvec.empty()) {
			int suboff = 0; // Cut off unaligned zeros from beginning of mask
			int tmp = maskvec.get(0);
			while (tmp != 0) {
				suboff += 1;
				tmp >>>= 8;
			}
			suboff = 4 - suboff; // 4 is sizeof int
			if (suboff != 0) {
				offset += suboff; // Slide up maskvec by suboff bytes
				for (int i = 0; i < maskvec.size() - 1; ++i) {
					tmp = maskvec.get(i) << (suboff * 8);
					tmp |= (maskvec.get(i + 1) >>> ((4 - suboff) * 8)); // 4 is sizeof int
					maskvec.set(i, tmp);
				}
				maskvec.setBack(maskvec.back() << (suboff * 8));
				for (int i = 0; i < valvec.size() - 1; ++i) { // Slide up valvec by suboff bytes
					tmp = valvec.get(i) << (suboff * 8);
					tmp |= (valvec.get(i + 1) >>> ((4 - suboff) * 8)); // 4 is sizeof int
					valvec.set(i, tmp);
				}
				valvec.setBack(valvec.back() << (suboff * 8));
			}

			iter1 = maskvec.end(); // Cut zeros from end of mask
			iter2 = valvec.end();
			while (!iter1.isBegin()) {
				iter1.decrement();
				iter2.decrement();
				if (iter1.get() != 0) {
					break; // Find last non-zero
				}
			}
			if (!iter1.isEnd()) {
				iter1.increment(); // Find first zero, in last zero chain
				iter2.increment();
			}
			maskvec.erase(iter1, maskvec.end());
			valvec.erase(iter2, valvec.end());
		}

		if (maskvec.empty()) {
			offset = 0;
			nonzerosize = 0; // Always true
			return;
		}
		nonzerosize = maskvec.size() * 4; // 4 is sizeof int
		int tmp = maskvec.back(); // tmp must be nonzero
		while ((tmp & 0xff) == 0) {
			nonzerosize -= 1;
			tmp >>>= 8;
		}
	}

	// Define mask and value pattern, confined to one int
	public PatternBlock(int off, int msk, int val) {
		offset = off;
		maskvec.push_back(msk);
		valvec.push_back(val);
		nonzerosize = 4; // 4 is sizeof int Assume all non-zero bytes before normalization
		normalize();
	}

	public PatternBlock(boolean tf) {
		offset = 0;
		if (tf) {
			nonzerosize = 0;
		}
		else {
			nonzerosize = -1;
		}
	}

	// Construct PatternBlock by ANDing two others together
	public PatternBlock(PatternBlock a, PatternBlock b) {
		PatternBlock res = a.intersect(b);
		offset = res.offset;
		nonzerosize = res.nonzerosize;
		maskvec = res.maskvec.copy();
		valvec = res.valvec.copy();
		res.dispose();
	}

	// AND several blocks together to construct new block
	public PatternBlock(VectorSTL<PatternBlock> list) {
		// PatternBlock *res,*next;

		if (list.empty()) { // If not ANDing anything
			offset = 0; // make constructed block always true
			nonzerosize = 0;
			return;
		}
		PatternBlock res = list.get(0);
		for (int i = 1; i < list.size(); ++i) {
			PatternBlock next = res.intersect(list.get(i));
			res.dispose();
			res = next;
		}
		offset = res.offset;
		nonzerosize = res.nonzerosize;
		maskvec = res.maskvec.copy();
		valvec = res.valvec.copy();
		res.dispose();
	}

	@Override
	public PatternBlock clone() {
		PatternBlock res = new PatternBlock(true);

		res.offset = offset;
		res.nonzerosize = nonzerosize;
		res.maskvec = maskvec.copy();
		res.valvec = valvec.copy();
		return res;
	}

	// The resulting pattern has a 1-bit in the mask
	// only if the two pieces have a 1-bit and the
	// values agree
	public PatternBlock commonSubPattern(PatternBlock b) {
		PatternBlock res = new PatternBlock(true);
		int maxlength = (getLength() > b.getLength()) ? getLength() : b.getLength();

		res.offset = 0;
		int offset1 = 0;
		while (offset1 < maxlength) {
			int mask1 = getMask(offset1 * 8, 4 * 8); // 4 is sizeof int
			int val1 = getValue(offset1 * 8, 4 * 8);
			int mask2 = b.getMask(offset1 * 8, 4 * 8);
			int val2 = b.getValue(offset1 * 8, 4 * 8);
			int resmask = mask1 & mask2 & ~(val1 ^ val2);
			int resval = val1 & val2 & resmask;
			res.maskvec.push_back(resmask);
			res.valvec.push_back(resval);
			offset1 += 4; // 4 is sizeof int
		}
		res.nonzerosize = maxlength;
		res.normalize();
		return res;
	}

	public PatternBlock intersect(PatternBlock b) {
		// Construct the intersecting pattern
		if (alwaysFalse() || b.alwaysFalse()) {
			return new PatternBlock(false);
		}
		PatternBlock res = new PatternBlock(true);
		int maxlength = (getLength() > b.getLength()) ? getLength() : b.getLength();

		res.offset = 0;
		int offset1 = 0;
		int mask1, val1, mask2, val2, commonmask;
		int resmask, resval;
		while (offset1 < maxlength) {
			mask1 = getMask(offset1 * 8, 4 * 8);
			val1 = getValue(offset1 * 8, 4 * 8);
			mask2 = b.getMask(offset1 * 8, 4 * 8);
			val2 = b.getValue(offset1 * 8, 4 * 8);
			commonmask = mask1 & mask2;	// Bits in mask shared by both patterns
			if ((commonmask & val1) != (commonmask & val2)) {
				res.nonzerosize = -1;	// Impossible pattern
				res.normalize();
				return res;
			}
			resmask = mask1 | mask2;
			resval = (mask1 & val1) | (mask2 & val2);
			res.maskvec.push_back(resmask);
			res.valvec.push_back(resval);
			offset1 += 4;
		}
		res.nonzerosize = maxlength;
		res.normalize();
		return res;
	}

	// does every masked bit in -this- match the corresponding
	// masked bit in -op2-
	public boolean specializes(PatternBlock op2) {
		int length = 8 * op2.getLength();
		int sbit = 0;
		while (sbit < length) {
			int tmplength = length - sbit;
			if (tmplength > 8 * 4) {
				tmplength = 8 * 4;
			}
			int mask1 = getMask(sbit, tmplength);
			int value1 = getValue(sbit, tmplength);
			int mask2 = op2.getMask(sbit, tmplength);
			int value2 = op2.getValue(sbit, tmplength);
			if ((mask1 & mask2) != mask2) {
				return false;
			}
			if ((value1 & mask2) != (value2 & mask2)) {
				return false;
			}
			sbit += tmplength;
		}
		return true;
	}

	// Do the mask and value match exactly
	public boolean identical(PatternBlock op2) {
		int length = 8 * op2.getLength();
		int tmplength = 8 * getLength();
		if (tmplength > length) {
			length = tmplength;		// Maximum of two lengths
		}

		int sbit = 0;
		while (sbit < length) {
			tmplength = length - sbit;
			if (tmplength > 8 * 4) {
				tmplength = 8 * 4;
			}
			int mask1 = getMask(sbit, tmplength);
			int value1 = getValue(sbit, tmplength);
			int mask2 = op2.getMask(sbit, tmplength);
			int value2 = op2.getValue(sbit, tmplength);
			if (mask1 != mask2) {
				return false;
			}
			if ((mask1 & value1) != (mask2 & value2)) {
				return false;
			}
			sbit += tmplength;
		}
		return true;
	}

	public int getMask(int startbit, int size) {
		startbit -= 8 * offset;
		// Note the division and remainder here is unsigned.  Then it is recast to signed. 
		// If startbit is negative, then wordnum1 is either negative or very big,
		// if (unsigned size is same as sizeof int)
		// In either case, shift should come out between 0 and 8*sizeof(uintm)-1
		int wordnum1 = Utils.unsignedDivide(startbit, (8 * 4)); // 4 is sizeof int
		int shift = Utils.unsignedModulo(startbit, (8 * 4));
		int wordnum2 = Utils.unsignedDivide((startbit + size - 1), (8 * 4));
		int res;

		if ((wordnum1 < 0) || (wordnum1 >= maskvec.size())) {
			res = 0;
		}
		else {
			res = maskvec.get(wordnum1);
		}

		res <<= shift;
		if (wordnum1 != wordnum2) {
			int tmp;
			if ((wordnum2 < 0) || (wordnum2 >= maskvec.size())) {
				tmp = 0;
			}
			else {
				tmp = maskvec.get(wordnum2);
			}
			res |= (tmp >>> (8 * 4 - shift));
		}
		res >>>= (8 * 4 - size);

		return res;
	}

	public int getValue(int startbit, int size) {
		startbit -= 8 * offset;
		int wordnum1 = Utils.unsignedDivide(startbit, (8 * 4));
		int shift = Utils.unsignedModulo(startbit, (8 * 4));
		int wordnum2 = Utils.unsignedDivide((startbit + size - 1), (8 * 4));
		int res;

		if ((wordnum1 < 0) || (wordnum1 >= valvec.size())) {
			res = 0;
		}
		else {
			res = valvec.get(wordnum1);
		}
		res <<= shift;
		if (wordnum1 != wordnum2) {
			int tmp;
			if ((wordnum2 < 0) || (wordnum2 >= valvec.size())) {
				tmp = 0;
			}
			else {
				tmp = valvec.get(wordnum2);
			}
			res |= (tmp >>> (8 * 4 - shift));
		}
		res >>>= (8 * 4 - size);

		return res;
	}

	public boolean isInstructionMatch(ParserWalker pos, int off) {
		if (nonzerosize <= 0) {
			return (nonzerosize == 0);
		}
		off += offset;
		for (int i = 0; i < maskvec.size(); ++i) {
			int data = pos.getInstructionBytes(off, 4);
			if ((maskvec.get(i) & data) != valvec.get(i)) {
				return false;
			}
			off += 4;
		}
		return true;
	}

	public boolean isContextMatch(ParserWalker pos, int off) {
		if (nonzerosize <= 0) {
			return (nonzerosize == 0);
		}
		off += offset;
		for (int i = 0; i < maskvec.size(); ++i) {
			int data = pos.getContextBytes(off, 4);
			if ((maskvec.get(i) & data) != valvec.get(i)) {
				return false;
			}
			off += 4;
		}
		return true;
	}

	public void saveXml(PrintStream s) {
		s.append("<pat_block ");
		s.append("offset=\"");
		s.print(offset);
		s.append("\" ");
		s.append("nonzero=\"");
		s.print(nonzerosize);
		s.append("\">\n");
		for (int i = 0; i < maskvec.size(); ++i) {
			s.append("  <mask_word ");
			s.append("mask=\"0x");
			s.append(Utils.toUnsignedIntHex(maskvec.get(i)));
			s.append("\" ");
			s.append("val=\"0x");
			s.append(Utils.toUnsignedIntHex(valvec.get(i)));
			s.append("\"/>\n");
		}
		s.append("</pat_block>\n");
	}

	public void restoreXml(Element el) {
		offset = XmlUtils.decodeUnknownInt(el.getAttributeValue("offset"));
		nonzerosize = XmlUtils.decodeUnknownInt(el.getAttributeValue("nonzero"));

		List<?> list = el.getChildren();
		Iterator<?> it = list.iterator();

		while (it.hasNext()) {
			Element subel = (Element) it.next();
			int mask = XmlUtils.decodeUnknownInt(subel.getAttributeValue("mask"));
			int val = XmlUtils.decodeUnknownInt(subel.getAttributeValue("val"));
			maskvec.push_back(mask);
			valvec.push_back(val);
		}
		normalize();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		//sb.append("(offset=" + offset + ",nonzero=" + nonzerosize + ")");
		for (int i = 0; i < offset; i++) {
			sb.append("........ ");
		}
		int pos = -1;
		for (int i = 0; i < maskvec.size(); i++) {
			int m = maskvec.get(i);
			int v = valvec.get(i);
			for (int j = 0; j < 32; j++) {
				if (j % 8 == 0) {
					pos++;
					if (pos >= nonzerosize) {
						return sb.toString();
					}
					if (i != 0 || j != 0) {
						sb.append(' ');
					}
				}
				if (m < 0) {
					if (v < 0) {
						sb.append('1');
					}
					else {
						sb.append('0');
					}
				}
				else {
					sb.append('.');
				}
				m <<= 1;
				v <<= 1;
			}
		}
		return sb.toString();
	}
}
