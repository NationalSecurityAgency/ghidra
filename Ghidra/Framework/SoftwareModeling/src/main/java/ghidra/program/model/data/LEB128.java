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
package ghidra.program.model.data;

import java.io.*;

/**
 * Logic for reading LEB128 values.
 * <p>
 * LEB128 is a variable length integer encoding that uses 7 bits per byte, with the high bit
 * being reserved as a continuation flag, with the least significant bytes coming first 
 * (<b>L</b>ittle <b>E</b>ndian <B>B</b>ase <b>128</b>).
 * <p>
 * This implementation only supports reading values that decode to at most 64 bits (to fit into
 * a java long).
 * <p>
 * When reading a value, you must already know if it was written as a signed or unsigned value to
 * be able to decode it correctly.
 */
public class LEB128 {
	/**
	 * Max number of bytes that is supported by the deserialization code.
	 */
	public static final int MAX_SUPPORTED_LENGTH = 10;

	/**
	 * Reads an unsigned LEB128 variable length integer from the stream.
	 * 
	 * @param is {@link InputStream} to get bytes from
	 * @return leb128 value, as a long
	 * @throws IOException if an I/O error occurs or decoded value is outside the range of a java
	 * 64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
	 * there is an error or EOF getting a byte from the InputStream before reaching the end of the
	 * encoded value
	 */
	public static long unsigned(InputStream is) throws IOException {
		return read(is, false);
	}

	/**
	 * Reads a signed LEB128 variable length integer from the stream.
	 * 
	 * @param is {@link InputStream} to get bytes from
	 * @return leb128 value, as a long
	 * @throws IOException if an I/O error occurs or decoded value is outside the range of a java
	 * 64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
	 * there is an error or EOF getting a byte from the InputStream before reaching the end of the
	 * encoded value
	 */
	public static long signed(InputStream is) throws IOException {
		return read(is, true);
	}

	/**
	 * Reads a LEB128 number from the stream and returns it as a java 64 bit long int.
	 * <p>
	 * Large unsigned integers that use all 64 bits are returned in a java native
	 * 'long' type, which is signed.  It is up to the caller to treat the value as unsigned.
	 * <p>
	 * Large integers that use more than 64 bits will cause an IOException to be thrown.
	 * <p>
	 * @param is {@link InputStream} to get bytes from
	 * @param isSigned true if the value is signed
	 * @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
	 * set to false
	 * @throws IOException if an I/O error occurs or decoded value is outside the range of a java
	 * 64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
	 * there is an error or EOF getting a byte from the InputStream before reaching the end of the
	 * encoded value
	 */
	public static long read(InputStream is, boolean isSigned) throws IOException {
		int nextByte = 0;
		int shift = 0;
		long value = 0;
		while (true) {
			nextByte = is.read();
			if (nextByte < 0) {
				throw new EOFException();
			}
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
			// 0x40 is the new 'high' sign bit since 0x80 is the continuation flag.
			// bitwise-or in all the sign-extension bits we need for the value
			value |= (-1L << shift);
		}

		return value;
	}

	/**
	 * Returns the length of the variable length LEB128 value.
	 *  
	 * @param is InputStream to get bytes from
	 * @return length of the LEB128 value, or -1 if the end of the value is not found
	 * @throws IOException if error getting next byte from stream
	 */
	public static int getLength(InputStream is) throws IOException {
		int length = 0;
		int nextByte;
		while ((nextByte = is.read()) >= 0 && length < MAX_SUPPORTED_LENGTH) {
			length++;
			if ((nextByte & 0x80) == 0) {
				return length;
			}
		}
		return -1;
	}

	/**
	 * Decodes a LEB128 number from a byte array and returns it as a long.
	 * <p>
	 * See {@link #read(InputStream, boolean)}
	 * 
	 * @param bytes the bytes representing the LEB128 number
	 * @param offset offset in byte array of where to start reading bytes 
	 * @param isSigned true if the value is signed
	 * @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
	 *	       set to false
	 * @throws IOException if array offset is invalid, decoded value is outside the range of a java
	 * 64 bit int (or it used more than {@value #MAX_SUPPORTED_LENGTH} bytes to be encoded), or 
	 * the end of the array was reached before reaching the end of the encoded value
	 */
	public static long decode(byte[] bytes, int offset, boolean isSigned) throws IOException {
		InputStream is = new ByteArrayInputStream(bytes, offset, bytes.length - offset);
		return read(is, isSigned);
	}

}
