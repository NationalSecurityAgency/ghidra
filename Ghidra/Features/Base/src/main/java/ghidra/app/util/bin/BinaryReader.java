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

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

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
	 */
	public boolean isValidIndex(int index) {
		return provider.isValidIndex(index & Conv.INT_MASK);
	}

	/**
	 * Returns true if the specified index into
	 * the underlying byte provider is valid.
	 * @param index the index in the byte provider
	 * @return returns true if the specified index is valid
	 */
	public boolean isValidIndex(long index) {
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
	 * Reads a null terminated US-ASCII string starting at the current index,
	 * advancing the current index by the length of the string that was found.
	 * <p>
	 * Note: this method no longer trims() the returned String.
	 * <p>
	 * 
	 * @return the US-ASCII string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextAsciiString() throws IOException {
		return readNextString(StandardCharsets.US_ASCII, 1);
	}

	/**
	 * Reads a fixed length US-ASCII string starting at the current index,
	 * advancing the current index by the specified fixed length.
	 * <p>
	 * Trailing null terminator characters will be removed.  (suitable for reading
	 * a string from a fixed length field that is padded with trailing null chars)
	 * <p>
	 * Note: this method no longer trims() the returned String.
	 * <p>
	 * @param length number of bytes to read
	 * @return the US-ASCII string at the current index
	 */
	public String readNextAsciiString(int length) throws IOException {
		return readNextString(length, StandardCharsets.US_ASCII, 1);
	}

	/**
	 * Reads a null-terminated UTF-16 Unicode string at the current index, 
	 * advancing the current index by the length of the string that was found.
	 * <p>
	 * 
	 * @return UTF-16 string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextUnicodeString() throws IOException {
		return readNextString(getUTF16Charset(), 2);
	}

	/**
	 * Reads a fixed length UTF-16 Unicode string at the current index,
	 * advancing the current index by the length of the string that was found.
	 * <p>
	 *
	 * @param charCount number of UTF-16 characters to read (not bytes)
	 * @return the UTF-16 Unicode string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextUnicodeString(int charCount) throws IOException {
		return readNextString(charCount, getUTF16Charset(), 2);
	}

	/**
	 * Reads a null-terminated UTF-8 string at the current index, 
	 * advancing the current index by the length of the string that was found.
	 * <p>
	 * 
	 * @return UTF-8 string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextUtf8String() throws IOException {
		return readNextString(StandardCharsets.UTF_8, 1);
	}

	/**
	 * Reads a fixed length UTF-8 string the current index,
	 * advancing the current index by the length of the string that was found.
	 * <p>
	 *
	 * @param length number of bytes to read
	 * @return the UTF-8 string at the current index
	 * @exception IOException if an I/O error occurs
	 */
	public String readNextUtf8String(int length) throws IOException {
		return readNextString(length, StandardCharsets.UTF_8, 1);
	}

	/**
	 * Reads a null terminated string starting at the current index, 
	 * using a specific {@link Charset}, advancing the current index by the length of 
	 * the string that was found.
	 * <p>
	 * @param charset {@link Charset}, see {@link StandardCharsets}
	 * @param charLen number of bytes in each character
	 * @return the string
	 * @exception IOException if an I/O error occurs
	 */
	private String readNextString(Charset charset, int charLen) throws IOException {
		byte[] bytes = readUntilNullTerm(currentIndex, charLen);
		currentIndex += bytes.length + charLen;

		String result = new String(bytes, charset);
		return result;
	}

	/**
	 * Reads a fixed length string of <code>charCount</code> characters
	 * starting at the current index, using a specific {@link Charset},
	 * advancing the current index by the length of the string that was found.
	 * <p>
	 * Trailing null terminator characters will be removed.  (suitable for reading
	 * a string from a fixed length field that is padded with trailing null chars)
	 * <p>
	 * @param index the index where the string begins
	 * @param charCount the number of charLen character elements to read
	 * @param charset {@link Charset}, see {@link StandardCharsets}
	 * @param charLen number of bytes in each character
	 * @return the string
	 * @exception IOException if an I/O error occurs
	 */
	private String readNextString(int charCount, Charset charset, int charLen) throws IOException {
		if (charCount < 0) {
			throw new IllegalArgumentException(String.format("Invalid charCount: %d", charCount));
		}
		byte[] bytes = readByteArray(currentIndex, charCount * charLen);
		currentIndex += bytes.length;

		int strLen = getLengthWithoutTrailingNullTerms(bytes, charLen);
		String result = new String(bytes, 0, strLen, charset);
		return result;
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

	//--------------------------------------------------------------------------------------------
	// String stuff
	//--------------------------------------------------------------------------------------------
	private byte[] readUntilNullTerm(long index, int charLen) throws IOException {
		long maxPos = provider.length() - charLen;
		if (index > maxPos) {
			throw new EOFException(String.format("Attempted to read string at 0x%x", index));
		}
		long curPos = index;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (; curPos <= maxPos; curPos += charLen) {
			byte[] bytes = readByteArray(curPos, charLen);
			if (isNullTerm(bytes, 0, charLen)) {
				return baos.toByteArray();
			}
			baos.write(bytes);
		}
		throw new EOFException(String.format("Unterminated string at 0x%x..0x%x", index, curPos));
	}

	private boolean isNullTerm(byte[] bytes, int offset, int charLen) {
		for (int i = offset; i < offset + charLen; i++) {
			if (bytes[i] != 0) {
				return false;
			}
		}
		return true;
	}

	private int getLengthWithoutTrailingNullTerms(byte[] bytes, int charLen) {
		int termPos = bytes.length - charLen;
		while (termPos >= 0 && isNullTerm(bytes, termPos, charLen)) {
			termPos -= charLen;
		}
		return termPos + charLen;
	}

	private Charset getUTF16Charset() {
		return isBigEndian() ? StandardCharsets.UTF_16BE : StandardCharsets.UTF_16LE;
	}

	/**
	 * Reads a null terminated US-ASCII string, starting at specified index, stopping at
	 * the first null character.
	 * <p>
	 * Note: this method no longer trims() the returned String.
	 * <p>
	 * 
	 * @param index starting position of the string
	 * @return US-ASCII string, excluding the trailing null terminator character
	 * @throws IOException if error reading bytes
	 */
	public String readAsciiString(long index) throws IOException {
		return readString(index, StandardCharsets.US_ASCII, 1);
	}

	/**
	 * Reads an fixed length US-ASCII string starting at <code>index</code>.
	 * <p>
	 * Trailing null terminator characters will be removed.  (suitable for reading
	 * a string from a fixed length field that is padded with trailing null chars)
	 * <p>
	 * Note: this method no longer trims() the returned String.
	 * <p>
	 * @param index where the string begins
	 * @param length number of bytes to read
	 * @return the US-ASCII string
	 * @exception IOException if an I/O error occurs
	 */
	public String readAsciiString(long index, int length) throws IOException {
		return readString(index, length, StandardCharsets.US_ASCII, 1);
	}

	/**
	 * Reads a null-terminated UTF-16 Unicode string starting at <code>index</code> and using 
	 * the pre-specified {@link #setLittleEndian(boolean) endianness}.
	 * <p>
	 * The end of the string is denoted by a two-byte (ie. short) <code>null</code> character.
	 * <p>
	 * @param index where the UTF-16 Unicode string begins
	 * @return the UTF-16 Unicode string
	 * @exception IOException if an I/O error occurs
	 */
	public String readUnicodeString(long index) throws IOException {
		return readString(index, getUTF16Charset(), 2);
	}

	/**
	 * Reads a fixed length UTF-16 Unicode string of <code>length</code> characters
	 * starting at <code>index</code>, using the pre-specified
	 * {@link #setLittleEndian(boolean) endianness}.
	 * <p>
	 * Trailing null terminator characters will be removed.  (suitable for reading
	 * a string from a fixed length field that is padded with trailing null chars)
	 * <p>
	 * @param index the index where the UTF-16 Unicode string begins
	 * @param charCount the number of UTF-16 character elements to read.
	 * @return the UTF-16 Unicode string
	 * @exception IOException if an I/O error occurs
	 */
	public String readUnicodeString(long index, int charCount) throws IOException {
		return readString(index, charCount, getUTF16Charset(), 2);
	}

	/**
	 * Reads a null-terminated UTF-8 string starting at <code>index</code>.
	 * <p>
	 * @param index where the UTF-8 string begins
	 * @return the string
	 * @exception IOException if an I/O error occurs
	 */
	public String readUtf8String(long index) throws IOException {
		return readString(index, StandardCharsets.UTF_8, 1);
	}

	/**
	 * Reads a fixed length UTF-8 string of <code>length</code> bytes
	 * starting at <code>index</code>.
	 * <p>
	 * Trailing null terminator characters will be removed.  (suitable for reading
	 * a string from a fixed length field that is padded with trailing null chars)
	 * <p>
	 * @param index the index where the UTF-8 string begins
	 * @param length the number of bytes to read
	 * @return the string
	 * @exception IOException if an I/O error occurs
	 */
	public String readUtf8String(long index, int length) throws IOException {
		return readString(index, length, StandardCharsets.UTF_8, 1);
	}

	/**
	 * Reads a fixed length string of <code>charCount</code> characters
	 * starting at <code>index</code>, using a specific {@link Charset}.
	 * <p>
	 * Trailing null terminator characters will be removed.  (suitable for reading
	 * a string from a fixed length field that is padded with trailing null chars)
	 * <p>
	 * @param index the index where the string begins
	 * @param charCount the number of charLen character elements to read
	 * @param charset {@link Charset}, see {@link StandardCharsets}
	 * @param charLen number of bytes in each character
	 * @return the string
	 * @exception IOException if an I/O error occurs
	 */
	private String readString(long index, int charCount, Charset charset, int charLen)
			throws IOException {
		if (charCount < 0) {
			throw new IllegalArgumentException(String.format("Invalid charCount: %d", charCount));
		}
		byte[] bytes = readByteArray(index, charCount * charLen);

		int strLen = getLengthWithoutTrailingNullTerms(bytes, charLen);
		String result = new String(bytes, 0, strLen, charset);
		return result;
	}

	/**
	 * Reads a null-terminated string starting at <code>index</code>, using a specific
	 * {@link Charset}.
	 * <p>
	 * @param index where the string begins
	 * @param charset {@link Charset}, see {@link StandardCharsets}
	 * @param charLen number of bytes in each character
	 * @return the string
	 * @exception IOException if an I/O error occurs
	 */
	private String readString(long index, Charset charset, int charLen) throws IOException {
		byte[] bytes = readUntilNullTerm(index, charLen);

		String result = new String(bytes, charset);
		return result;
	}

	//--------------------------------------------------------------------------------------------
	// end String stuff
	//--------------------------------------------------------------------------------------------

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
	 * Returns the underlying byte provider.
	 * @return the underlying byte provider
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

}
