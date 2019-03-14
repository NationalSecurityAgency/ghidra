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
package mdemangler;

import java.nio.charset.Charset;

/**
 * This class represents "string" within a Microsoft mangled symbol.
 */
public class MDString extends MDParsableItem {
	private String name;
	private byte[] byteArray;
	private String byteString;
	private char charType;
	private int typeSize;
	private boolean crcPass;
	private int lenVal;
	private long crcVal;
	private boolean hasAddr = false;
	private long addrVal = 0;

	// TODO: Look into Ghidra types: AsciiDataType (replaced by charDataType?),
	//  WideChar16DataType, WideChar32DataType, and WideCharDataType.

	public MDString(MDMang dmang) {
		super(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		// MDMANG SPECIALIZATION USED.
		dmang.insert(builder, this);
	}

	public boolean isUnicode() {
		return (charType == '1');
	}

	public byte[] getBytes() {
		return byteArray;
	}

	public int getLength() {
		return lenVal;
	}

	public String getName() {
		return name;
	}

	public boolean hasAddress() {
		return hasAddr;
	}

	public long getAddress() {
		return addrVal;
	}

	public String getString(Charset charset8, Charset charset16) {
		if (byteString == null) {
			int index;
			switch (typeSize) {
				case 2:
					byteString = new String(byteArray, charset16);
					break;
				case 1:
				default:
					byteString = new String(byteArray, charset8);
					break;
			}
			for (index = 0; index < byteString.length(); index++) {
				if (byteString.charAt(index) == '\u0000') {
					byteString = byteString.substring(0, index);
					break;
				}
			}
		}
		return byteString;
	}

	public boolean crcPass() {
		return crcPass;
	}

	// Information gleaned from lists.cs.uiuc.edu/pipermail/cfe-commits/Week-of-
	//  Mon-20150324/101952.html
	// '??_C@_' <char-type> <literal-length> <encoded-crc> <encoded-string> '@'
	// where:
	//  <char-type> = 0 if char
	//              = 1 if wchar_t
	//              = ??? for char16_t and char32_t
	//  <literal-length> = <non-negative integer>       # length of the literal
	//                                                  # The string literal does not consider
	//                                                     the NUL terminator byte(s) but the
	//                                                     mangling does.
	//                                                  # The length is in terms of bytes, not
	//                                                     characters
	//                                                  # mangleNumber(byteLength = charByteWidth)
	//                                                     ???
	//  <encoded-crc> = <hex digit>+ @                  # crc of the literal including
	//                                                     null-terminator
	//  <encoded-string> = <simple character>           # for an uninteresting character
	//                                                     [a-z|A-Z|0-9|_|$]
	//                   = ?$<hex digit> <hex digit>    # theses two nibbles encode the byte for
	//                                                     the character
	//                   = ?[a-z]                       # 0xe1 - 0xfa 
	//                   = ?[A-Z]                       # 0xc1 - 0xda 
	//                   = ?[0-9]                       # [,/\:. \n\t'-] 
	//                                                  # Has up to 32 characters (of the
	//                                                     character type).
	@Override
	protected void parseInternal() throws MDException {
		name = "";
		// Up to this point the following characters have been stripped: '??_C'
		if (dmang.getAndIncrement() != '@') {
			throw new MDException("MDString parse error: missing @");
		}
		if (dmang.getAndIncrement() != '_') {
			throw new MDException("MDString parse error: missing _");
		}
		charType = dmang.getAndIncrement();
		MDEncodedNumber len = new MDEncodedNumber(dmang);
		len.parse();
		lenVal = len.getValue().intValue();
		MDEncodedNumber crcNumber = new MDEncodedNumber(dmang);
		crcNumber.parse();
		crcVal = crcNumber.getValue().longValue();
		switch (charType) {
			case '0': // char string
				typeSize = 1;
				name = "`string'";
				break;
			case '1': // wchar_t string
				typeSize = 2;
				name = "`string'";
				break;
			default:
				typeSize = 1;
				name = "`string'";
				// name = "MDString: Microsoft string of unknown type: " + charType;
				break;
		}
		if ((lenVal % typeSize) != 0) {
			// error... which we are currently ignoring
		}
		parseByteArray();
		if (dmang.peek() != MDMang.DONE) {
			MDEncodedNumber addr = new MDEncodedNumber(dmang);
			addr.parse();
			addrVal = addr.getValue().longValue();
			hasAddr = true;
		}
		if (lenVal <= (32 * typeSize)) {
			CrcChecker checker = new CrcChecker();
			crcPass = checker.crcCheck(byteArray, crcVal, typeSize);
		}
		else {
			// Returning true for now, as we do not have the data needed to calculate the CRC.
			crcPass = true;
		}
	}

	private byte parseByte() throws MDException {
		byte b = 0;
		char c = dmang.getAndIncrement();
		if (Character.isLetter(c) || Character.isDigit(c) || c == '_' || c == '$') {
			b = (byte) c;
		}
		else if (c == '?') {
			if ((dmang.peek() == MDMang.DONE)) {
				throw new MDException("MDString parse error: not enough data");
			}
			c = dmang.getAndIncrement();
			if (c >= 'a' && c <= 'z') {
				b = (byte) (c - 'a' + 0xe1);
			}
			else if (c >= 'A' && c <= 'Z') {
				b = (byte) (c - 'A' + 0xc1);
			}
			else {
				switch (c) {
					case '0':
						b = (byte) (',');
						break;
					case '1':
						b = (byte) ('/');
						break;
					case '2':
						b = (byte) ('\\');
						break;
					case '3':
						b = (byte) (':');
						break;
					case '4':
						b = (byte) ('.');
						break;
					case '5':
						b = (byte) (' ');
						break;
					case '6':
						b = (byte) ('\n');
						break;
					case '7':
						b = (byte) ('\t');
						break;
					case '8':
						b = (byte) ('\'');
						break;
					case '9':
						b = (byte) ('-');
						break;
					case '$':
						if ((dmang.peek() == MDMang.DONE)) {
							throw new MDException("MDString parse error: not enough data");
						}
						c = dmang.getAndIncrement();
						if (c < 'A' || c > ('A' + 15)) {
							throw new MDException("MDString parse error: invalid hex code:" + c);
						}
						b = (byte) ((c - 'A') << 4);
						if ((dmang.peek() == MDMang.DONE)) {
							throw new MDException("MDString parse error: not enough data");
						}
						c = dmang.getAndIncrement();
						if (c < 'A' || c > ('A' + 15)) {
							throw new MDException("MDString parse error: invalid hex code:" + c);
						}
						b |= (byte) (c - 'A');
						break;
					default:
						throw new MDException("MDString parse error: invalid code2: " + c);
				}
			}
		}
		else {
			throw new MDException("MDString parse error: invalid code1:" + c);
		}
		return b;
	}

	private void parseByteArray() throws MDException {
		byteArray = new byte[lenVal];
		int index = 0;
		while ((dmang.peek() != '@') && (index < lenVal)) {
			byteArray[index++] = parseByte();
		}
		dmang.increment(); // Skip terminating '@'
	}

	/**
	 * This class is responsible for performing Cyclic Redundancy Check (CRC) calculations
	 * using the CRC-32 polynomial and prefill.
	 */
	private class CrcChecker {
		long crc;

		private long reflectBits(long val) {
			int i = 0;
			long newVal = 0L;
			for (i = 0; i < 32; i++) {
				newVal >>= 1;
				newVal |= val & 0X80000000L;
				val <<= 1;
			}
			return newVal;
		}

		private void crcCalc(byte val) {
			long longByte = val;
			for (int i = 0; i < 8; i++) {
				crc <<= 1;
				if ((((crc >> 32) ^ longByte) & 0x01L) != 0x00L) {
					crc ^= 0x04c11db7L; // xor with polynomial
				}
				longByte >>= 1;
			}
		}

		/**
		 * Performs the CRC calculation.
		 * @param bytes the array of bytes upon which to perform the calculation.
		 * @param crcTest the value to compare the result with.
		 * @return true if the calculation matches crcTest; false otherwise.
		 */
		private boolean crcCheck(byte[] bytes, long crcTest, int size) {
			int index;
			crc = 0xffffffffL;
			for (index = 0; index < bytes.length; index += size) {
				for (int internalIndex = size - 1; internalIndex >= 0; internalIndex--) {
					crcCalc(bytes[index + internalIndex]);
				}
			}
			crc &= 0xffffffffL;
			crc = reflectBits(crc);
			return (crc == crcTest);
		}
	}
}

/******************************************************************************/
/******************************************************************************/
