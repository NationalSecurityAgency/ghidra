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

import ghidra.util.*;

/**
 * A class for reading data from a
 * generic byte provider in either big-endian or little-endian.
 *
 *
 */
public class BinaryReader {
	/**
	 * The size of a BYTE in Java.
	 */
	public final static int SIZEOF_BYTE = 1;
	/**
	 * The size of a SHORT in Java.
	 */
	public final static int SIZEOF_SHORT = 2;
	/**
	 * The size of an INTEGER in Java.
	 */
	public final static int SIZEOF_INT = 4;
	/**
	 * The size of a LONG in Java.
	 */
	public final static int SIZEOF_LONG = 8;

	private final ByteProvider provider;
	private DataConverter converter;
	private long currentIndex;

	/**
	 * Constructs a reader using the given ByteProvider and endian-order.
	 *
	 * If isLittleEndian is true, then all values read
	 * from the file will be done so assuming
	 * little-endian order.
	 *
	 * Otherwise, if isLittleEndian
	 * is false, then all values will be read
	 * assuming big-endian order.
	 *
	 * @param provider the byte provider
	 * @param isLittleEndian the endian-order
	 */
	public BinaryReader(ByteProvider provider, boolean isLittleEndian) {
		this(provider, DataConverter.getInstance(!isLittleEndian), 0);
	}
	
	/**
	 * Creates a BinaryReader instance.
	 * 
	 * @param provider the ByteProvider to use
	 * @param converter the {@link DataConverter} to use
	 * @param initialIndex the initial offset
	 */
	public BinaryReader(ByteProvider provider, DataConverter converter, long initialIndex) {
		this.provider = provider;
		this.converter = converter;
		this.currentIndex = initialIndex;
	}

	/**
	 * Returns a clone of this reader, with its own independent current position,
	 * positioned at the new index.
	 *  
	 * @param newIndex the new index
	 * @return an independent clone of this reader positioned at the new index
	 */
	public BinaryReader clone(long newIndex) {
		return new BinaryReader(provider, converter, newIndex);
	}

	/**
	 * Returns an independent clone of this reader positioned at the same index.
	 * 
	 * @return a independent clone of this reader positioned at the same index
	 */
	@Override
	public BinaryReader clone() {
		return clone(currentIndex);
	}

	/**
	 * Returns a BinaryReader that is in BigEndian mode.
	 * 
	 * @return a new independent BinaryReader, at the same position, in BigEndian mode
	 */
	public BinaryReader asBigEndian() {
		return new BinaryReader(provider, BigEndianDataConverter.INSTANCE, currentIndex);
	}

	/**
	 * Returns a BinaryReader that is in LittleEndian mode.
	 * 
	 * @return a new independent instance, at the same position, in LittleEndian mode
	 */
	public BinaryReader asLittleEndian() {
		return new BinaryReader(provider, LittleEndianDataConverter.INSTANCE, currentIndex);
	}

	/**
	 * Returns true if this reader will extract values in little endian,
	 * otherwise in big endian.
	 * @return true is little endian, false is big endian
	 */
	public boolean isLittleEndian() {
		return converter instanceof LittleEndianDataConverter;
	}

	/**
	 * Returns true if this reader will extract values in big endian.
	 * 
	 * @return true is big endian, false is little endian
	 */
	public boolean isBigEndian() {
		return converter instanceof BigEndianDataConverter;
	}

	/**
	 * Sets the endian of this binary reader.
	 * @param isLittleEndian true for little-endian and false for big-endian
	 */
	public void setLittleEndian(boolean isLittleEndian) {
		converter = DataConverter.getInstance(!isLittleEndian);
	}

	/**
	 * Returns the length of the underlying file.
	 * @return returns the length of the underlying file
	 * @exception IOException if an I/O error occurs
	 */
	public long length() throws IOException {
		return provider.length();
	}

	/**
	 * Returns true if the specified index into
	 * the underlying byte provider is valid.
	 * @param index the index in the byte provider
	 * @return returns true if the specified index is valid
	 * @exception IOException if an I/O error occurs
	 */
	public boolean isValidIndex(int index) throws IOException {
		return provider.isValidIndex(index & Conv.INT_MASK);
	}

	/**
	 * Returns true if the specified index into
	 * the underlying byte provider is valid.
	 * @param index the index in the byte provider
	 * @return returns true if the specified index is valid
	 * @exception IOException if an I/O error occurs
	 */
	public boolean isValidIndex(long index) throws IOException {
		return provider.isValidIndex(index);
	}

	/**
	 * Aligns the current index on the specified alignment value.
	 * For example, if current index was 123 and align value was
	 * 16, then current index would become 128.
	 * @param alignValue
	 * @return the number of bytes required to align
	 */
	public int align(int alignValue) {
		long align = currentIndex % alignValue;
		if (align == 0) {
			return 0;
		}
		currentIndex = currentIndex + (alignValue - align);
		return (int) (alignValue - align);
	}

	////////////////////////////////////////////////////////////////////

	/**
	 * A convenience method for setting the index using a 32 bit integer.
	 * 
	 * @param index new index, treated as a 32 bit unsigned integer 
	 */
	public void setPointerIndex(int index) {
		this.currentIndex = Integer.toUnsignedLong(index);
	}

	/**
	 * Sets the current index to the specified value.
	 * The pointer index will allow the reader
	 * to operate as a psuedo-iterator.
	 *
	 * @param index the byte provider index value
	 */
	public void setPointerIndex(long index) {
		this.currentIndex = index;
	}

	/**
	 * Returns the current index value.
	 * @return the current index value
	 */
	public long getPointerIndex() {
		return currentIndex;
	}

	/**
	 * Peeks at the next byte without incrementing
	 * the current index.
	 * @return the next byte
	 * @exception IOException if an I/O error occurs
	 */
	public byte peekNextByte() throws IOException {
		return readByte(currentIndex);
	}

	/**
	 * Peeks at the next short without incrementing
	 * the current index.
	 * @return the next short
	 * @exception IOException if an I/O error occurs
	 */
	public short peekNextShort() throws IOException {
		return readShort(currentIndex);
	}

	/**
	 * Peeks at the next integer without incrementing
	 * the current index.
	 * @return the next int
	 * @exception IOException if an I/O error occurs
	 */
	public int peekNextInt() throws IOException {
		return readInt(currentIndex);
	}

	/**
	 * Peeks at the next long without incrementing
	 * the current index.
	 * @return the next long
	 * @exception IOException if an I/O error occurs
	 */
	public long peekNextLong() throws IOException {
		return readLong(currentIndex);
	}

	/**
	 * Reads the byte at the current index and then increments the current
	 * index by <code>SIZEOF_BYTE</code>.
	 * @return the byte at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public byte readNextByte() throws IOException {
		byte b = readByte(currentIndex);
		currentIndex += SIZEOF_BYTE;
		return b;
	}

	/**
	 * Reads the unsigned byte at the current index and then increments the current
	 * index by <code>SIZEOF_BYTE</code>.
	 * @return the unsigned byte at the current index, as an int
	 * @exception IOException if an I/O error occurs
	 */
	public int readNextUnsignedByte() throws IOException {
		return readNextByte() & NumberUtil.UNSIGNED_BYTE_MASK;
	}

	/**
	 * Reads the short at the current index and then increments the current
	 * index by <code>SIZEOF_SHORT</code>.
	 * @return the short at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public short readNextShort() throws IOException {
		short s = readShort(currentIndex);
		currentIndex += SIZEOF_SHORT;
		return s;
	}

	/**
	 * Reads the unsigned short at the current index and then increments the current
	 * index by <code>SIZEOF_SHORT</code>.
	 * @return the unsigned short at the current index, as an int
	 * @exception IOException if an I/O error occurs
	 */
	public int readNextUnsignedShort() throws IOException {
		return readNextShort() & NumberUtil.UNSIGNED_SHORT_MASK;
	}

	/**
	 * Reads the integer at the current index and then increments the current
	 * index by <code>SIZEOF_INT</code>.
	 * @return the integer at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public int readNextInt() throws IOException {
		int i = readInt(currentIndex);
		currentIndex += SIZEOF_INT;
		return i;
	}

	/**
	 * Reads the unsigned integer at the current index and then increments the current
	 * index by <code>SIZEOF_INT</code>.
	 * @return the unsigned integer at the current index, as a long
	 * @exception IOException if an I/O error occurs
	 */
	public long readNextUnsignedInt() throws IOException {
		return readNextInt() & NumberUtil.UNSIGNED_INT_MASK;
	}

	/**
	 * Reads the long at the current index and then increments the current
	 * index by <code>SIZEOF_LONG</code>.
	 * @return the long at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public long readNextLong() throws IOException {
		long l = readLong(currentIndex);
		currentIndex += SIZEOF_LONG;
		return l;
	}

	/**
	 * Reads the Ascii string at the current index and then increments the current
	 * index by the length of the Ascii string that was found. This method
	 * expects the string to be null-terminated.
	 * @return the null-terminated Ascii string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextAsciiString() throws IOException {
		String s = readAsciiString(currentIndex);
		currentIndex += (s.length() + 1);
		return s;
	}

	/**
	 * Reads a null terminated Ascii string starting at the current index,
	 * ending at the first null character or when reaching the
	 * end of the underlying ByteProvider.
	 * <p>
	 * The current index is advanced to the next byte after the null terminator.
	 * <p>
	 * @return the null-terminated Ascii string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextNullTerminatedAsciiString() throws IOException {
		StringBuilder buffer = new StringBuilder();
		while (currentIndex < provider.length()) {
			byte b = provider.readByte(currentIndex++);
			if (b == 0) {
				break;
			}
			buffer.append((char) b);
		}
		return buffer.toString();
	}

	/**
	 * Reads an Ascii string of <code>length</code>
	 * characters starting at the current index and then increments the current
	 * index by <code>length</code>.
	 *
	 * @return the Ascii string at the current index
	 */
	public String readNextAsciiString(int length) throws IOException {
		String s = readAsciiString(currentIndex, length);
		currentIndex += length;
		return s;
	}

	/**
	 * Reads the Unicode string at the current index and then increments the current
	 * index by the length of the Unicode string that was found. This method
	 * expects the string to be double null-terminated ('\0\0').
	 * @return the null-terminated Ascii string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextUnicodeString() throws IOException {
		String s = readUnicodeString(currentIndex);
		currentIndex += ((s.length() + 1) * 2);
		return s;
	}

	/**
	 * Reads fixed length UTF-16 Unicode string the current index and then increments the current
	 * {@link #setPointerIndex(int) pointer index} by <code>length</code> elements (length*2 bytes).
	 *
	 * @return the UTF-16 Unicode string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextUnicodeString(int length) throws IOException {
		String s = readUnicodeString(currentIndex, length);
		currentIndex += (length * 2);
		return s;
	}

	/**
	 * Reads a byte array of <code>nElements</code>
	 * starting at the current index and then increments the current
	 * index by <code>SIZEOF_BYTE * nElements</code>.
	 * @return the byte array starting at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public byte[] readNextByteArray(int nElements) throws IOException {
		byte[] b = readByteArray(currentIndex, nElements);
		currentIndex += (SIZEOF_BYTE * nElements);
		return b;
	}

	/**
	 * Reads a short array of <code>nElements</code>
	 * starting at the current index and then increments the current
	 * index by <code>SIZEOF_SHORT * nElements</code>.
	 * @return the short array starting at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public short[] readNextShortArray(int nElements) throws IOException {
		short[] s = readShortArray(currentIndex, nElements);
		currentIndex += (SIZEOF_SHORT * nElements);
		return s;
	}

	/**
	 * Reads an integer array of <code>nElements</code>
	 * starting at the current index and then increments the current
	 * index by <code>SIZEOF_INT * nElements</code>.
	 * @return the integer array starting at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public int[] readNextIntArray(int nElements) throws IOException {
		int[] i = readIntArray(currentIndex, nElements);
		currentIndex += (SIZEOF_INT * nElements);
		return i;
	}

	/**
	 * Reads a long array of <code>nElements</code>
	 * starting at the current index and then increments the current
	 * index by <code>SIZEOF_LONG * nElements</code>.
	 * @return the long array starting at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public long[] readNextLongArray(int nElements) throws IOException {
		long[] l = readLongArray(currentIndex, nElements);
		currentIndex += (SIZEOF_LONG * nElements);
		return l;
	}

	////////////////////////////////////////////////////////////////////

	/**
	 * Reads an Ascii string starting at <code>index</code>, ending
	 * at the next character outside the range [32..126] or when
	 * reaching the end of the underlying ByteProvider.
	 * <p>
	 * Leading and trailing spaces will be trimmed before the string is returned.
	 *
	 * @param index the index where the Ascii string begins
	 * @return the trimmed Ascii string
	 * @exception IOException if an I/O error occurs
	 */
	public String readAsciiString(long index) throws IOException {
		StringBuilder buffer = new StringBuilder();
		long len = provider.length();
		while (true) {
			if (index == len) {
				// reached the end of the bytes and found no non-ascii data
				break;
			}
			byte b = provider.readByte(index++);
			if ((b >= 32) && (b <= 126)) {
				buffer.append((char) b);
			}
			else {
				break;
			}
		}
		return buffer.toString().trim();
	}

	/**
	 * Returns an Ascii string of <code>length</code> bytes
	 * starting at <code>index</code>. This method does not
	 * care about null-terminators.  Leading and trailing spaces
	 * will be trimmed before the string is returned.
	 * @param index the index where the Ascii string begins
	 * @param length the length of the Ascii string
	 * @return the trimmed Ascii string
	 * @exception IOException if an I/O error occurs
	 */
	public String readAsciiString(long index, int length) throws IOException {
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < length; ++i) {
			byte b = provider.readByte(index++);
			buffer.append((char) (b & 0x00FF));
		}
		return buffer.toString().trim();
	}

	/**
	 * Reads an Ascii string starting at <code>index</code>, ending
	 * at the next {@code termChar} character byte or when  reaching the end of
	 * the underlying ByteProvider.
	 * <p>
	 * Does NOT trim the string.
	 * <p>
	 * @param index the index where the Ascii string begins
	 * @return the Ascii string (excluding the terminating character)
	 * @exception IOException if an I/O error occurs
	 */
	public String readTerminatedString(long index, char termChar) throws IOException {
		StringBuilder buffer = new StringBuilder();
		long len = provider.length();
		while (index < len) {
			char c = (char) provider.readByte(index++);
			if (c == termChar) {
				break;
			}
			buffer.append(c);
		}
		return buffer.toString();
	}

	/**
	 * Reads an Ascii string starting at <code>index</code>, ending
	 * at the next character that is one of the specified {@code termChars} or when
	 * reaching the end of the underlying ByteProvider.
	 * <p>
	 * Does NOT trim the string.
	 * <p>
	 * @param index the index where the Ascii string begins
	 * @return the Ascii string (excluding the terminating character)
	 * @exception IOException if an I/O error occurs
	 */
	public String readTerminatedString(long index, String termChars) throws IOException {
		StringBuilder buffer = new StringBuilder();
		long len = provider.length();
		while (index < len) {
			char c = (char) provider.readByte(index++);
			if (termChars.indexOf(c) != -1) {
				break;
			}
			buffer.append(c);
		}
		return buffer.toString();
	}

	/**
	 * Reads an fixed length Ascii string starting at <code>index</code>.
	 * <p>
	 * Does NOT trim the string.
	 * <p>
	 * @param index the index where the Ascii string begins
	 * @param len number of bytes to read
	 * @return the Ascii string
	 * @exception IOException if an I/O error occurs
	 */
	public String readFixedLenAsciiString(long index, int len) throws IOException {
		byte[] bytes = readByteArray(index, len);
		return new String(bytes);
	}

	/**
	 * Reads a null-terminated UTF-16 Unicode string starting
	 * at <code>index</code> using the pre-specified
	 * {@link #setLittleEndian(boolean) endianness}.
	 * <p>
	 * The end of the string is denoted by a two-byte (ie. short) <code>null</code> character.
	 * <p>
	 * Leading and trailing spaces will be trimmed before the string is returned.
	 * <p>
	 * @param index the index where the UTF-16 Unicode string begins
	 * @return the trimmed UTF-16 Unicode string
	 * @exception IOException if an I/O error occurs
	 */
	public String readUnicodeString(long index) throws IOException {
		StringBuilder buffer = new StringBuilder();
		while (index < length()) {
			int ch = readUnsignedShort(index);
			if (ch == 0) {
				break;
			}
			buffer.append((char) ch);
			index += 2;
		}
		return buffer.toString().trim();
	}

	/**
	 * Reads a fixed length UTF-16 Unicode string of <code>length</code> characters
	 * starting at <code>index</code>, using the pre-specified
	 * {@link #setLittleEndian(boolean) endianness}.
	 * <p>
	 * This method does not care about null-terminators.
	 * <p>
	 * Leading and trailing spaces will be trimmed before the string is returned.
	 * <p>
	 * @param index the index where the UTF-16 Unicode string begins
	 * @param length the number of UTF-16 character elements to read.
	 * @return the trimmed UTF-16 Unicode string
	 * @exception IOException if an I/O error occurs
	 */
	public String readUnicodeString(long index, int length) throws IOException {
		StringBuilder buffer = new StringBuilder(length);
		long endOffset = index + (length * 2);
		while (index < endOffset) {
			int ch = readUnsignedShort(index);
			buffer.append((char) ch);
			index += 2;
		}
		return buffer.toString().trim();
	}

	/**
	 * Returns the signed BYTE at <code>index</code>.
	 * @param index the index where the BYTE begins
	 * @return the signed BYTE
	 * @exception IOException if an I/O error occurs
	 */
	public byte readByte(long index) throws IOException {
		return provider.readByte(index);
	}

	/**
	 * Returns the unsigned BYTE at <code>index</code>.
	 * @param index the index where the BYTE begins
	 * @return the unsigned BYTE as an int
	 * @exception IOException if an I/O error occurs
	 */
	public int readUnsignedByte(long index) throws IOException {
		return readByte(index) & NumberUtil.UNSIGNED_BYTE_MASK;
	}

	/**
	 * Returns the signed SHORT at <code>index</code>.
	 * @param index the index where the SHORT begins
	 * @return the signed SHORT
	 * @exception IOException if an I/O error occurs
	 */
	public short readShort(long index) throws IOException {
		byte[] bytes = provider.readBytes(index, SIZEOF_SHORT);
		return converter.getShort(bytes);
	}

	/**
	 * Returns the unsigned SHORT at <code>index</code>.
	 * @param index the index where the SHORT begins
	 * @return the unsigned SHORT as an int
	 * @exception IOException if an I/O error occurs
	 */
	public int readUnsignedShort(long index) throws IOException {
		return readShort(index) & NumberUtil.UNSIGNED_SHORT_MASK;
	}

	/**
	 * Returns the signed INTEGER at <code>index</code>.
	 * @param index the index where the INTEGER begins
	 * @return the signed INTEGER
	 * @exception IOException if an I/O error occurs
	 */
	public int readInt(long index) throws IOException {
		byte[] bytes = provider.readBytes(index, SIZEOF_INT);
		return converter.getInt(bytes);
	}

	/**
	 * Returns the unsigned INTEGER at <code>index</code>.
	 * @param index the index where the INTEGER begins
	 * @return the unsigned INTEGER as a long
	 * @exception IOException if an I/O error occurs
	 */
	public long readUnsignedInt(long index) throws IOException {
		return readInt(index) & NumberUtil.UNSIGNED_INT_MASK;
	}

	/**
	 * Returns the signed LONG at <code>index</code>.
	 * @param index the index where the LONG begins
	 * @return the LONG
	 * @exception IOException if an I/O error occurs
	 */
	public long readLong(long index) throws IOException {
		byte[] bytes = provider.readBytes(index, SIZEOF_LONG);
		return converter.getLong(bytes);
	}

	/**
	 * Returns the signed value of the integer (of the specified length) at the specified offset.
	 * 
	 * @param index offset the offset from the membuffers origin (the address that it is set at) 
	 * @param len the number of bytes that the integer occupies.  Valid values are 1 (byte), 2 (short),
	 * 4 (int), 8 (long)
	 * @return value of requested length, with sign bit extended, in a long
	 * @throws IOException 
	 */
	public long readValue(long index, int len) throws IOException {
		byte[] bytes = provider.readBytes(index, len);
		return converter.getSignedValue(bytes, len);
	}

	/**
	 * Returns the unsigned value of the integer (of the specified length) at the specified offset.
	 * 
	 * @param index offset the offset from the membuffers origin (the address that it is set at) 
	 * @param len the number of bytes that the integer occupies.  Valid values are 1 (byte), 2 (short),
	 * 4 (int), 8 (long)
	 * @return unsigned value of requested length, in a long
	 * @throws IOException 
	 */
	public long readUnsignedValue(long index, int len) throws IOException {
		byte[] bytes = provider.readBytes(index, len);
		return converter.getValue(bytes, len);
	}

	/**
	 * Returns the BYTE array of <code>nElements</code>
	 * starting at <code>index</code>.
	 * @param index the index where the BYTE begins
	 * @param nElements the number of array elements
	 * @return the BYTE array
	 * @exception IOException if an I/O error occurs
	 */
	public byte[] readByteArray(long index, int nElements) throws IOException {
		if (nElements < 0) {
			throw new IOException("Invalid number of elements specified: " + nElements);
		}
		return provider.readBytes(index, nElements);
	}

	/**
	 * Returns the SHORT array of <code>nElements</code>
	 * starting at <code>index</code>.
	 * @param index the index where the SHORT begins
	 * @param nElements the number of array elements
	 * @return the SHORT array
	 * @exception IOException if an I/O error occurs
	 */
	public short[] readShortArray(long index, int nElements) throws IOException {
		if (nElements < 0) {
			throw new IOException("Invalid number of elements specified: " + nElements);
		}
		short[] arr = new short[nElements];
		for (int i = 0; i < nElements; ++i) {
			arr[i] = readShort(index);
			index += SIZEOF_SHORT;
		}
		return arr;
	}

	/**
	 * Returns the INTEGER array of <code>nElements</code>
	 * starting at <code>index</code>.
	 * @param index the index where the INTEGER begins
	 * @param nElements the number of array elements
	 * @return the INTEGER array
	 * @exception IOException if an I/O error occurs
	 */
	public int[] readIntArray(long index, int nElements) throws IOException {
		if (nElements < 0) {
			throw new IOException("Invalid number of elements specified: " + nElements);
		}
		int[] arr = new int[nElements];
		for (int i = 0; i < nElements; ++i) {
			arr[i] = readInt(index);
			index += SIZEOF_INT;
		}
		return arr;
	}

	/**
	 * Returns the LONG array of <code>nElements</code>
	 * starting at <code>index</code>.
	 * @param index the index where the LONG begins
	 * @param nElements the number of array elements
	 * @return the LONG array
	 * @exception IOException if an I/O error occurs
	 */
	public long[] readLongArray(long index, int nElements) throws IOException {
		if (nElements < 0) {
			throw new IOException("Invalid number of elements specified: " + nElements);
		}
		long[] arr = new long[nElements];
		for (int i = 0; i < nElements; ++i) {
			arr[i] = readLong(index);
			index += SIZEOF_LONG;
		}
		return arr;
	}

	/**
	 * Returns the Ascii string array of <code>nElements</code>
	 * starting at <code>index</code>
	 * @param index the index where the Ascii Strings begin
	 * @param nElements the number of array elements
	 * @return the Ascii String array
	 * @exception IOException if an I/O error occurs
	 */
	public String[] readAsciiStringArray(long index, int nElements) throws IOException {
		if (nElements < 0) {
			throw new IOException("Invalid number of elements specified: " + nElements);
		}
		String[] arr = new String[nElements];
		for (int i = 0; i < nElements; ++i) {
			String tmp = readAsciiString(index);
			arr[i] = tmp;
			index += (tmp == null ? 1 : tmp.length());
		}
		return arr;
	}

	/**
	 * Returns the underlying byte provider.
	 * @return the underlying byte provider
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

}
