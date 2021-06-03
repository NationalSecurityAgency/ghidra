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
import ghidra.app.util.bin.ByteArrayProvider;

/**
 * Class to hold result of reading a LEB128 value, along with size and position metadata.
 * <p>
 * Note: If a LEB128 value that would result in a native value longer than 64bits is attempted to
 * be read, an {@link IOException} will be thrown, and the stream's position will be left at the last read byte.
 * <p>
 * If this was a valid (but overly large) LEB128, the caller's stream will be left still pointing to LEB data.
 * <p>
 */
public class LEB128 {

	private final long offset;
	private final long value;
	private final int byteLength;

	private LEB128(long offset, long value, int byteLength) {
		this.offset = offset;
		this.value = value;
		this.byteLength = byteLength;
	}

	/**
	 * Returns the value as an unsigned int32.  If the actual value
	 * is outside the positive range of a java int (ie. 0.. {@link Integer#MAX_VALUE}),
	 * an exception is thrown.
	 *    
	 * @return int in the range of 0 to  {@link Integer#MAX_VALUE}
	 * @throws IOException if value is outside range
	 */
	public int asUInt32() throws IOException {
		ensureInt32u(value);
		return (int) value;
	}

	/**
	 * Returns the value as an signed int32.  If the actual value
	 * is outside the range of a java int (ie.  {@link Integer#MIN_VALUE}.. {@link Integer#MAX_VALUE}),
	 * an exception is thrown.
	 *    
	 * @return int in the range of {@link Integer#MIN_VALUE} to  {@link Integer#MAX_VALUE}
	 * @throws IOException if value is outside range
	 */
	public int asInt32() throws IOException {
		ensureInt32s(value);
		return (int) value;
	}
	
	/**
	 * Returns the value as a 64bit primitive long.  Interpreting the signed-ness of the
	 * value will depend on the way the value was read (ie. if {@link #readSignedValue(BinaryReader)}
	 * vs. {@link #readUnsignedValue(BinaryReader)} was used).
	 * 
	 * @return long value.
	 */
	public long asLong() { 
		return value;
	}

	/**
	 * Returns the offset of the LEB128 value in the stream it was read from.
	 *   
	 * @return stream offset of the LEB128 value
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the number of bytes that were used to store the LEB128 value in the stream
	 * it was read from.
	 * 
	 * @return number of bytes used to store the read LEB128 value
	 */
	public int getLength() {
		return byteLength;
	}

	@Override
	public String toString() {
		return String.format("LEB128: value: %d, offset: %d, byteLength: %d", value, offset,
			byteLength);
	}

	/**
	 * Reads a LEB128 value from the BinaryReader and returns a {@link LEB128} instance
	 * that contains the value along with size and position metadata.
	 * <p>
	 * See {@link #readAsLong(BinaryReader, boolean)}.
	 * 
	 * @param reader {@link BinaryReader} to read bytes from
	 * @param isSigned true if the value is signed
	 * @return a {@link LEB128} instance with the read LEB128 value with metadata
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int
	 */
	public static LEB128 readValue(BinaryReader reader, boolean isSigned) throws IOException {
		long offset = reader.getPointerIndex();
		long value = LEB128.readAsLong(reader, isSigned);
		int size = (int) (reader.getPointerIndex() - offset);
		return new LEB128(offset, value, size);
	}

	/**
	 * Reads an unsigned LEB128 value from the BinaryReader and returns a {@link LEB128} instance
	 * that contains the value along with size and position metadata.
	 * <p>
	 * See {@link #readAsLong(BinaryReader, boolean)}.
	 * 
	 * @param reader {@link BinaryReader} to read bytes from
	 * @return a {@link LEB128} instance with the read LEB128 value with metadata
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int
	 */
	public static LEB128 readUnsignedValue(BinaryReader reader) throws IOException {
		return readValue(reader, false);
	}

	/**
	 * Reads an signed LEB128 value from the BinaryReader and returns a {@link LEB128} instance
	 * that contains the value along with size and position metadata.
	 * <p>
	 * See {@link #readAsLong(BinaryReader, boolean)}.
	 * 
	 * @param reader {@link BinaryReader} to read bytes from
	 * @return a {@link LEB128} instance with the read LEB128 value with metadata
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int
	 */
	public static LEB128 readSignedValue(BinaryReader reader) throws IOException {
		return readValue(reader, true);
	}

	/**
	 * Reads a LEB128 signed number from the BinaryReader and returns it as a java 32 bit int.
	 * <p>
	 * If the value of the number can not fit in the int type, an {@link IOException} will
	 * be thrown.
	 *
	 * @param reader {@link BinaryReader} to read bytes from
	 * @return signed int32 value
	 * @throws IOException if error reading bytes or value is outside the
	 * range of a signed int32
	 */
	public static int readAsInt32(BinaryReader reader) throws IOException {
		long tmp = readAsLong(reader, true);
		ensureInt32s(tmp);
		return (int) tmp;
	}

	/**
	 * Reads a LEB128 unsigned number from the BinaryReader and returns it as a java 32 bit int.
	 * <p>
	 * If the value of the number can not fit in the positive range of the int type,
	 * an {@link IOException} will be thrown.
	 *
	 * @param reader {@link BinaryReader} to read bytes from
	 * @return unsigned int32 value 0..Integer.MAX_VALUE
	 * @throws IOException if error reading bytes or value is outside the
	 * positive range of a java 32 bit int (ie. 0..Integer.MAX_VALUE)
	 */
	public static int readAsUInt32(BinaryReader reader) throws IOException {
		long tmp = readAsLong(reader, false);
		ensureInt32u(tmp);
		return (int) tmp;
	}

	/**
	 * Reads a LEB128 number from the BinaryReader and returns it as a java 64 bit long int.
	 * <p>
	 * Large unsigned integers that use all 64 bits are be returned in a java native
	 * 'long' type, which is signed.  It is up to the caller to treat the value as unsigned.
	 * <p>
	 * Large integers that use more than 64 bits will cause an IOException to be thrown.
	 * <p>
	 * @param reader {@link BinaryReader} to read bytes from
	 * @param isSigned true if the value is signed
	 * @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
	 * set to false
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int 
	 */
	public static long readAsLong(BinaryReader reader, boolean isSigned) throws IOException {
		int nextByte = 0;
		int shift = 0;
		long value = 0;
		while (true) {
			nextByte = reader.readNextUnsignedByte();
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
			// 0x40 is the new 'high' sign bit since 0x80 is the continuation flag
			value |= (-1L << shift);
		}

		return value;
	}

	/**
	 * Decodes a LEB128 number from a byte array and returns it as a long.
	 * <p>
	 * See {@link #readAsLong(BinaryReader, boolean)}.
	 * 
	 * @param bytes the bytes representing the LEB128 number
	 * @param isSigned true if the value is signed
	 * @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
	 * set to false
	 * @throws IOException if error reading bytes or value is outside the
	 * range of a java 64 bit int
	 */
	public static long decode(byte[] bytes, boolean isSigned) throws IOException {
		return decode(bytes, 0, isSigned);
	}

	/**
	 * Decodes a LEB128 number from a byte array and returns it as a long.
	 * <p>
	 * See {@link #readAsLong(BinaryReader, boolean)}.
	 * 
	 * @param bytes the bytes representing the LEB128 number
	 * @param offset offset in byte array of where to start reading bytes 
	 * @param isSigned true if the value is signed
	 * @return long integer value.  Caller must treat it as unsigned if isSigned parameter was
	 * set to false
	 * @throws IOException if error reading bytes or value is outside the
	 * range of a java 64 bit int
	 */
	public static long decode(byte[] bytes, int offset, boolean isSigned) throws IOException {
		ByteArrayProvider bap = new ByteArrayProvider(bytes);
		BinaryReader br = new BinaryReader(bap, true);
		br.setPointerIndex(offset);
		return readAsLong(br, isSigned);
	}

	private static void ensureInt32u(long value) throws IOException {
		if (value < 0 || value > Integer.MAX_VALUE) {
			throw new IOException("LEB128 value out of range for java 32 bit unsigned int: " +
				Long.toUnsignedString(value));
		}
	}

	private static void ensureInt32s(long value) throws IOException {
		if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
			throw new IOException(
				"LEB128 value out of range for java 32 bit signed int: " +
					Long.toString(value));
		}
	}

}
