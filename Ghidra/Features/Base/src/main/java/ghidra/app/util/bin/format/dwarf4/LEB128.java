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
package ghidra.app.util.bin.format.dwarf4;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.NumberUtil;
public final class LEB128 {

	/**
	 * Decode a LEB128 signed number and return it as a java 32 bit int.
	 * <p>
	 * If the value of the number can not fit in the int type, an {@link IOException} will
	 * be thrown.
	 *
	 * @param reader
	 * @return
	 * @throws IOException
	 */
	public static int decode32s(BinaryReader reader) throws IOException {
		long tmp = decode(reader, true);
		if (tmp < Integer.MIN_VALUE || tmp > Integer.MAX_VALUE) {
			throw new IOException(
				"LEB128 value out of range for java 32 bit signed int: " + Long.toString(tmp));
		}

		return (int) tmp;
	}

	/**
	 * Decode a LEB128 unsigned number and return it as a java 32 bit int.
	 * <p>
	 * If the value of the number can not fit in the positive range of the int type,
	 * an {@link IOException} will be thrown.
	 *
	 * @param reader
	 * @return
	 * @throws IOException
	 */
	public static int decode32u(BinaryReader reader) throws IOException {
		long tmp = decode(reader, false);

		// NOTE: will only be lt 0 if tmp's value was larger than what fits in signed long and it wrapped.
		if (tmp < 0 || tmp > Integer.MAX_VALUE) {
			throw new IOException("LEB128 value out of range for java 32 bit unsigned int: " +
				Long.toUnsignedString(tmp));
		}

		return (int) tmp;
	}

	/**
	 * Decodes a LEB128 number using a binary reader and stores it in a long.
	 * <p>
	 * Large unsigned integers that use 64 bits will be returned in java's native
	 * 'long' type, which is signed.  It is up to the caller to treat the value as unsigned.
	 * <p>
	 * Large integers that use more than 64 bits will cause an IOException to be thrown.
	 * <p>
	 * @param reader the binary reader
	 * @param isSigned true if the value is signed
	 * @throws IOException if an I/O error occurs
	 */
	public static long decode(BinaryReader reader, boolean isSigned) throws IOException {
		int nextByte = 0;
		int shift = 0;
		long value = 0;
		boolean overflow = false;
		while (true) {
			nextByte = reader.readNextUnsignedByte();
			if (shift == 70 || (isSigned == false && shift == 63 && nextByte > 1)) {
				// if the value being read is more than 64 bits long mark it as overflow.
				// keep reading the rest of the number so the caller is not left in the
				// middle of the LEB128 number's guts.
				overflow = true;
			}

			// must cast to long before shifting otherwise shift values greater than 32 cause problems
			value |= ((long) (nextByte & 0x7F)) << shift;
			shift += 7;

			if ((nextByte & 0x80) == 0) {
				break;
			}
		}
		if (overflow) {
			throw new IOException(
				"Unsupported LEB128 value, too large to fit in 64bit java long variable");
		}
		if ((isSigned) && (shift < Long.SIZE) && ((nextByte & 0x40) != 0)) {
			value |= -(1 << shift);
		}

		return value;
	}

	/**
	 * Decodes a LEB128 number using a byte array and stores it in a long.
	 * This function cannot read numbers larger than Long.MAX_VALUE.
	 * @param bytes the bytes representing the LEB128 number
	 * @param isSigned true if the value is signed
	 * @throws IOException
	 */
	public static long decode(byte[] bytes, boolean isSigned) throws IOException {
		return decode(bytes, 0, isSigned);
	}

	/**
	 * Decodes a LEB128 number using an offset into a byte array and stores it in a long.
	 * This function cannot read numbers larger than Long.MAX_VALUE.
	 * @param bytes the bytes representing the LEB128 number
	 * @param offset offset into the byte array
	 * @param isSigned true if the value is signed
	 * @throws IOException
	 */
	public static long decode(byte[] bytes, int offset, boolean isSigned) throws IOException {
		int nextByte = 0;
		int shift = 0;
		long value = 0;
		for (int i = offset; i < bytes.length; i++) {
			nextByte = bytes[i] & NumberUtil.UNSIGNED_BYTE_MASK;

			if (shift == 70 || (isSigned == false && shift == 63 && nextByte > 1)) {
				throw new IOException(
					"Unsupported LEB128 value, too large to fit in 64bit java long variable");
			}

			// must cast to long before shifting otherwise shift values greater than 32 cause problems
			value |= ((long) (nextByte & 0x7F)) << shift;

			shift += 7;

			if ((nextByte & 0x80) == 0) {
				break;
			}
		}
		if ((isSigned) && (shift < Long.SIZE) && ((nextByte & 0x40) != 0)) {
			long tmp1 = (1L << shift);
			long tmp2 = -tmp1;
			value |= tmp2;
		}

		return value;
	}
}
