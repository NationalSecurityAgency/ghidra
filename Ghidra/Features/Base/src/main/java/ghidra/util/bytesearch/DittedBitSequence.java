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
package ghidra.util.bytesearch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.zip.CRC32;

import ghidra.xml.XmlPullParser;

/**
 * A pattern of bits/mask to match to a stream of bytes.  The bits/mask can be of any length.
 * The sequence can be initialized by:
 * 
 *    a string
 *    an array of bytes (no mask)
 *    an array of bytes and for mask
 *    
 *  The dits represent bits(binary) or nibbles(hex) that are don't care, for example:
 *     0x..d.4de2 ....0000 .1...... 00101101 11101001
 *  where 0x starts a hex number and '.' is a don't care nibble (hex) or bit (binary)
 */

public class DittedBitSequence {

	//Given a byte 0-255 (NOT a signed byte), retrieves its popcount.
	public static int[] popcount = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, //0-15
		1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, //16-31
		1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, //32-47
		2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, //48-63
		1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, //64-79
		2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, //80-95
		2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, //96-111
		3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, //112-127
		1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, //128-143
		2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, //144-159
		2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, //160-175
		3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, //176-191
		2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, //192-207
		3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, //208-223
		3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, //224-239
		4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8  //240-255
	};

	private int index;		// Unique index assigned to this sequence
	private byte[] bits;		// value bits contained in the sequence
	private byte[] dits;		// a 1 indicates the bit is not ditted

	public DittedBitSequence() {
		bits = null;
		dits = null;
	}

	/**
	 * Constructor from a ditted-bit-sequence string where white space is ignored (e.g., "10..11.0");
	 * 
	 * @param dittedBitData ditted sequence specified as a string
	 * 
	 * @throws IllegalArgumentException if invalid dittedBitData specified
	 */
	public DittedBitSequence(String dittedBitData) {
		initFromDittedStringData(dittedBitData);
	}

	/**
	 * Constructor from a ditted-bit string where white space is ignored.  If there are no dits,
	 * {@code hex} is true, and {@code hex} does not begin with {code 0x}, {@code 0x} will be
	 * prepended to the string before constructing the {@link DittedBitSequence}.
	 * @param dittedBitData string of bits and dits or hex numbers and dits (e.g., 0.1..0, 0xAB..)
	 * @param hex true to force hex on the sequence
	 */
	public DittedBitSequence(String dittedBitData, boolean hex) {
		if (hex && !dittedBitData.contains(".")) {
			if (!dittedBitData.startsWith("0x")) {
				dittedBitData = "0x" + dittedBitData;
			}
		}
		initFromDittedStringData(dittedBitData);
	}

	/**
	 * Copy contructor
	 * @param op2 is bit sequence being copied
	 */
	public DittedBitSequence(DittedBitSequence op2) {
		bits = op2.bits;
		dits = op2.dits;
	}

	/**
	 * @return value bytes
	 */
	public byte[] getValueBytes() {
		return bits.clone();
	}

	/**
	 * @return mask bytes which correspond to value bytes
	 */
	public byte[] getMaskBytes() {
		return dits.clone();
	}

	/**
	 * Construct a sequence of bytes to search for. No bits are masked off.
	 * 
	 * @param bytes byte values that must match
	 */
	public DittedBitSequence(byte[] bytes) {
		bits = bytes;
		dits = new byte[bytes.length];
		for (int i = 0; i < bytes.length; ++i) {
			dits[i] = (byte) 0xff;
		}
	}

	/**
	 * Construct a bit pattern to search for consisting of
	 * 0 bits, 1 bits, and don't care bits
	 * @param bytes is an array of bytes indicating the 0 and 1 bits that are cared about
	 * @param mask is an array of bytes masking off the bits that should be cared about, a 0 indicates a "don't care"
	 */
	public DittedBitSequence(byte[] bytes, byte[] mask) {
		bits = bytes;
		dits = mask;
	}

	//Smallest ditted sequence commensurate with two other ditted sequences.
	public DittedBitSequence(DittedBitSequence s1, DittedBitSequence s2) {
		this.bits = new byte[s1.bits.length];
		this.dits = new byte[s1.bits.length];

		for (int i = 0; i < this.bits.length; i++) {
			int tempInt = (s1.dits[i] & s2.dits[i] & (0xff ^ s1.bits[i] ^ s2.bits[i]));
			this.dits[i] = (byte) tempInt;
			this.bits[i] = (byte) (s1.bits[i] & s2.bits[i]);
		}
	}

	@Override
	public int hashCode() {
		CRC32 crc = new CRC32();
		crc.update(bits);
		crc.update(dits);
		return (int) crc.getValue();
	}

	//TODO: this notion of equality requires to sequences to have the same value
	//on a particular bit even if that bit is ditted.  Is this correct?
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		DittedBitSequence op2 = (DittedBitSequence) obj;
		if (bits.length != op2.bits.length) {
			return false;
		}
		for (int i = 0; i < bits.length; ++i) {
			if (bits[i] != op2.bits[i]) {
				return false;
			}
			if (dits[i] != op2.dits[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Concatenates a sequence to the end of another sequence and
	 * returns a new sequence.
	 * 
	 * @param toConat sequence to concatenate to this sequence
	 * 
	 * @return a new sequence that is the concat of this and toConcat
	 */
	public DittedBitSequence concatenate(DittedBitSequence toConat) {
		DittedBitSequence res = new DittedBitSequence();
		res.bits = new byte[bits.length + toConat.bits.length];
		res.dits = new byte[res.bits.length];
		for (int i = 0; i < bits.length; ++i) {
			res.bits[i] = bits[i];
			res.dits[i] = dits[i];
		}
		for (int i = 0; i < toConat.bits.length; ++i) {
			res.bits[bits.length + i] = toConat.bits[i];
			res.dits[bits.length + i] = toConat.dits[i];
		}

		return res;
	}

	/**
	 * Check for a match of a value at a certain offset in the pattern.
	 * An outside matcher will keep track of the match position within this
	 * ditted bit sequence.  Then call this method to match.
	 * 
	 * @param pos position in the pattern to match
	 * @param val a byte to be match at the given byte offset in the pattern
	 * 
	 * @return true if the byte matches the sequence mask/value
	 */
	public boolean isMatch(int pos, int val) {
		if (pos >= bits.length) {
			return false;
		}
		return ((byte) (val & dits[pos])) == bits[pos];
	}

	/**
	 * Set a an index in a larger sequence, or identifing id on this pattern
	 * 
	 * @param index - index in match sequence, or unique id
	 */
	public void setIndex(int index) {
		this.index = index;
	}

	/**
	 * Get the index or identifying id attached to this pattern
	 * 
	 * @return index or unique id attached to this sequence
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * get the size of this sequence in bytes
	 * 
	 * @return size in bytes
	 */
	public int getSize() {
		return bits.length;
	}

	/**
	 * Get number of bits that must be 0/1
	 * 
	 * @return number of bits that are not don't care (ditted)
	 */
	public int getNumFixedBits() {
		int popcnt = 0;
		for (byte dit : dits) {
			popcnt += popcount[0xff & dit];
		}
		return popcnt;
	}

	/**
	 * Get number of bits that are ditted (don't care)
	 * 
	 * @return number of ditted bits (don't care)
	 */
	public int getNumUncertainBits() {
		int popcnt = 0;
		for (byte dit : dits) {
			popcnt += popcount[0xff & dit];
		}
		return 8 * dits.length - popcnt;
	}

	public void writeBits(StringBuffer buf) {
		for (int chunk = 0; chunk < this.bits.length; chunk++) {
			buf.append(' ');
			byte dchomp = this.dits[chunk];
			int bchomp = this.bits[chunk];
			for (int pos = 128; pos > 0; pos >>>= 1) {
				if ((dchomp & pos) == 0) {
					buf.append('.');
				}
				else {
					buf.append((bchomp & pos) != 0 ? '1' : '0');
				}
			}
		}
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		writeBits(buf);
		return buf.toString();
	}

	/**
	 * get a ditted hex string representing this sequence
	 * 
	 * @return ditted hex string
	 */
	public String getHexString() {
		String uncompressed = this.toString();
		String[] parts = uncompressed.trim().split(" ");
		StringBuilder sb = new StringBuilder();
		for (int i = 0, max = parts.length; i < max; ++i) {
			if (parts[i].contains(".")) {
				sb.append(parts[i]);
				if (i != (max - 1)) {
					sb.append(" ");
				}
				continue;
			}
			String hexByte = Integer.toHexString(Integer.parseUnsignedInt(parts[i].trim(), 2));
			if (hexByte.length() < 2) {
				hexByte = "0" + hexByte;
			}
			sb.append("0x");
			sb.append(hexByte);
			if (i != (max - 1)) {
				sb.append(" ");
			}
		}
		return sb.toString();
	}

	/**
	 * restore ditted string from XML stream with hex/binary ditted sequences in the form:
	 *    <data> 0x..d.4de2 ....0000 .1...... 00101101 11101001 </data>
	 * where 0x starts a hex number and '.' is a don't care nibble (hex) or bit (binary)
	 * 
	 * @param parser XML pull parser stream
	 * 
	 * @return number of bytes read from XML <data> tag
	 * 
	 * @throws IOException if XML read has an error
	 */
	protected int restoreXmlData(XmlPullParser parser) throws IOException {
		parser.start("data");
		String text = parser.end().getText();
		try {
			return initFromDittedStringData(text);
		}
		catch (IllegalArgumentException e) {
			throw new IOException(
				"Bad <data> tag in at line " + parser.getLineNumber() + " : " + text);
		}
	}

	/**
	 * Initialize this sequence with a ditted sequence from a string in the form
	 *    (e.g. - 011...1., 0x.F, 01110011 0xAB)
	 *    
	 * @param text ditted sequence
	 * 
	 * @return number of bytes in the ditted sequence
	 * 
	 * @throws IllegalArgumentException if string is malformed
	 */
	private int initFromDittedStringData(String text) throws IllegalArgumentException {
		int markOffset = -1;
		int mode = -1; // -1: looking for start, -2: skip to EOL, 0: hex mode, 1: binary mode
		ArrayList<Byte> ditarray = new ArrayList<Byte>();
		ArrayList<Byte> bitarray = new ArrayList<Byte>();
		int i = 0;
		while (i < text.length()) {
			char c1, c2;
			c1 = text.charAt(i);
			if (mode == -2 && c1 != '\n') {
				i += 1;
				continue;
			}
			if (Character.isWhitespace(c1)) {
				mode = -1;
				i += 1;
				continue;
			}
			if (c1 == '#') { // start comment - skip remainder of line 
				mode = -2;
				i += 1;
				continue;
			}
			if (mode == -1) {
				if (c1 == '0') {
					c2 = text.charAt(i + 1);
					if (c2 == 'x') {
						mode = 0;			// Normal hexdecimal mode
						i += 2;
						continue;
					}
				}
				else if (c1 == '*') {
					markOffset = ditarray.size();		// Set mark at current number of bytes specified
					i += 1;
					continue;
				}
				else if ((c1 == '0') || (c1 == '1') || (c1 == '.')) {
					mode = 1;
				}
				else {
					throw new IllegalArgumentException("Bad ditted bit sequence");
				}
			}
			if (mode == 0) {
				c2 = text.charAt(i + 1);
				i += 2;
				int val = 0;
				int mask = 0xff;
				if (c1 == '.') {
					mask ^= 0xf0;
				}
				else {
					val = Character.getNumericValue(c1) << 4;
				}
				if (c2 == '.') {
					mask ^= 0xf;
				}
				else {
					val |= Character.getNumericValue(c2);
				}

				bitarray.add(Byte.valueOf((byte) val));
				ditarray.add(Byte.valueOf((byte) mask));
			}
			else {
				int val = 0;
				int mask = 0;
				for (int j = 0; j < 8; ++j) {
					c1 = text.charAt(i + j);
					if (c1 == '0') {
						val <<= 1;
						mask <<= 1;
						mask |= 1;
					}
					else if (c1 == '.') {
						val <<= 1;
						mask <<= 1;
					}
					else {
						val <<= 1;
						val |= 1;
						mask <<= 1;
						mask |= 1;
					}
				}
				i += 8;
				bitarray.add(Byte.valueOf((byte) val));
				ditarray.add(Byte.valueOf((byte) mask));
			}
		}
		bits = new byte[bitarray.size()];
		dits = new byte[ditarray.size()];
		for (int k = 0; k < bits.length; ++k) {
			bits[k] = bitarray.get(k).byteValue();
			dits[k] = ditarray.get(k).byteValue();
		}
		return markOffset;
	}

	/**
	 * Get the number of bits that are fixed, not ditted (don't care)
	 * 
	 * @param marked number of bytes in the pattern to check
	 * 
	 * @return number of initial fixed bits
	 */
	public int getNumInitialFixedBits(int marked) {
		if (dits == null) {
			return 0;
		}
		if ((marked <= 0) || (marked > dits.length)) {
			return 0;//perhaps return -1 instead?
		}
		int popcnt = 0;
		for (int i = 0; i < marked; ++i) {
			popcnt += popcount[0xff & dits[i]];
		}
		return popcnt;
	}
}
