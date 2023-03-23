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
package ghidra.app.util.bin;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.listing.Program;

/**
 * Class to hold result of reading a {@link LEB128} value, along with size and position metadata.
 */
public class LEB128Info {

	/**
	 * Reads an unsigned LEB128 value from the BinaryReader and returns a {@link LEB128Info} instance
	 * that contains the value along with size and position metadata.
	 * <p>
	 * @param reader {@link BinaryReader} to read bytes from
	 * @return a {@link LEB128Info} instance with the read LEB128 value with metadata
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int
	 */
	public static LEB128Info unsigned(BinaryReader reader) throws IOException {
		return readValue(reader, false);
	}

	/**
	 * Reads an signed LEB128 value from the BinaryReader and returns a {@link LEB128Info} instance
	 * that contains the value along with size and position metadata.
	 * <p>
	 * @param reader {@link BinaryReader} to read bytes from
	 * @return a {@link LEB128Info} instance with the read LEB128 value with metadata
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int
	 */
	public static LEB128Info signed(BinaryReader reader) throws IOException {
		return readValue(reader, true);
	}

	private final long offset;
	private final long value;
	private final int byteLength;

	private LEB128Info(long offset, long value, int byteLength) {
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
	 * value will depend on the way the value was read (ie. if {@link #signed(BinaryReader)}
	 * vs. {@link #unsigned(BinaryReader)} was used).
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
	 * Reads a LEB128 value from the BinaryReader and returns a {@link LEB128Info} instance
	 * that contains the value along with size and position metadata.
	 * <p>
	 * @param reader {@link BinaryReader} to read bytes from
	 * @param isSigned true if the value is signed
	 * @return a {@link LEB128Info} instance with the read LEB128 value with metadata
	 * @throws IOException if an I/O error occurs or value is outside the range of a java
	 * 64 bit int
	 */
	public static LEB128Info readValue(BinaryReader reader, boolean isSigned) throws IOException {
		long offset = reader.getPointerIndex();
		long value = LEB128.read(reader.getInputStream(), isSigned);
		int size = (int) (reader.getPointerIndex() - offset);
		return new LEB128Info(offset, value, size);
	}


	private static void ensureInt32u(long value) throws IOException {
		if (value < 0 || value > Integer.MAX_VALUE) {
			throw new InvalidDataException(
				"Value out of range for positive java 32 bit unsigned int: %s"
						.formatted(Long.toUnsignedString(value)));
		}
	}

	private static void ensureInt32s(long value) throws IOException {
		if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
			throw new InvalidDataException(
				"Value out of range for java 32 bit signed int: %d".formatted(value));
		}
	}

}
