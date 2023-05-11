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

	// jvm's will typically refuse to allocate arrays that are exactly Integer.MAX_VALUE.  
	// This is a conservative stab at a max array element count since we don't have a requirement
	// to reach exactly 2g elements
	private static final int MAX_SANE_BUFFER = Integer.MAX_VALUE - 1024;

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

	/**
	 * Reads and returns an object from the current position in the specified BinaryReader.
	 * <p>
	 * When reading from the BinaryReader, use "readNext" methods to consume the location where
	 * the object was located.
	 * <p>
	 * See {@link #get(BinaryReader)}
	 * 
	 * @param <T> the type of object that will be returned
	 */
	public interface ReaderFunction<T> {
		/**
		 * Reads from the specified {@link BinaryReader} and returns a new object instance.
		 * <p>
		 * When reading from the BinaryReader, use "readNext" methods to consume the location where
		 * the object was located.
		 * <p>
		 * Implementations of this method should not return {@code null}, instead they should
		 * throw an IOException.
		 *  
		 * @param reader {@link BinaryReader}
		 * @return new object
		 * @throws IOException if error reading
		 */
		T get(BinaryReader reader) throws IOException;
	}

	/**
	 * Reads and returns an object from the current position in the specified input stream.
	 * <p>
	 * 
	 * @param <T> the type of object that will be returned
	 */
	public interface InputStreamReaderFunction<T> {
		/**
		 * Reads from the specified input stream and returns a new object instance.
		 * <p>
		 * Implementations of this method should not return {@code null}, instead they should
		 * throw an IOException.
		 *  
		 * @param is an {@link InputStream} view of the BinaryReader
		 * @return new object
		 * @throws IOException if error reading
		 */
		T get(InputStream is) throws IOException;
	}

	protected final ByteProvider provider;
	protected DataConverter converter;
	protected long currentIndex;

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
	 * 
	 * @return returns the length of the underlying file
	 * @exception IOException if an I/O error occurs
	 */
	public long length() throws IOException {
		return provider.length();
	}

	/**
	 * Returns true if the specified unsigned int32 index into the underlying byte provider is
	 * valid.
	 * 
	 * @param index an integer that is treated as an unsigned int32 index into the byte provider
	 * @return returns true if the specified index is valid
	 */
	public boolean isValidIndex(int index) {
		return provider.isValidIndex(Integer.toUnsignedLong(index));
	}

	/**
	 * Returns true if the specified index into the underlying byte provider is valid.
	 * 
	 * @param index the index in the byte provider
	 * @return returns true if the specified index is valid
	 */
	public boolean isValidIndex(long index) {
		return provider.isValidIndex(index);
	}

	/**
	 * Returns true if the specified range is valid and does not wrap around the end of the 
	 * index space.
	 * 
	 * @param startIndex the starting index to check, treated as an unsigned int64
	 * @param count the number of bytes to check
	 * @return boolean true if all bytes between startIndex to startIndex+count (exclusive) are 
	 * valid (according to the underlying byte provider)
	 */
	public boolean isValidRange(long startIndex, int count) {
		if (count < 0) {
			return false;
		}
		if (count > 1) {
			// check the end of the range first to fail fast

			long endIndex = startIndex + (count - 1);
			if (Long.compareUnsigned(endIndex, startIndex) < 0) {
				// the requested range [startIndex..startIndex+count] wraps around the int64 to 0, so fail
				return false;
			}

			if (!provider.isValidIndex(endIndex)) {
				return false;
			}
			count--; // don't check the last element twice
		}
		for (int i = 0; i < count; i++) {
			if (!provider.isValidIndex(startIndex + i)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if this stream has data that could be read at the current position.
	 * 
	 * @return true if there are more bytes that could be read at the 
	 * {@link #getPointerIndex() current index}.
	 */
	public boolean hasNext() {
		return provider.isValidIndex(currentIndex);
	}

	/**
	 * Returns true if this stream has data that could be read at the current position.
	 *
	 * @param count number of bytes to verify
	 * @return true if there are at least count more bytes that could be read at the 
	 * {@link #getPointerIndex() current index}.
	 */
	public boolean hasNext(int count) {
		return isValidRange(currentIndex, count);
	}

	/**
	 * Advances the current index so that it aligns to the specified value (if not already
	 * aligned).
	 * <p>
	 * For example, if current index was 123 and align value was 16, then current index would
	 * be advanced to 128.
	 * 
	 * @param alignValue
	 * @return the number of bytes required to align (0..alignValue-1)
	 */
	public int align(int alignValue) {
		long prevIndex = currentIndex;
		currentIndex = NumericUtilities.getUnsignedAlignedValue(currentIndex, alignValue);
		return (int) (currentIndex - prevIndex);
	}

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
	 * to operate as a pseudo-iterator.
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
	 * Returns an InputStream that is a live view of the BinaryReader's position.
	 * <p>
	 * Any bytes read with the stream will affect the current position of the BinaryReader, and
	 * any change to the BinaryReader's position will affect the next value the inputstream returns.
	 *  
	 * @return {@link InputStream}
	 */
	public InputStream getInputStream() {
		return new BinaryReaderInputStream();
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
		return Byte.toUnsignedInt(readNextByte());
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
		return Short.toUnsignedInt(readNextShort());
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
		return Integer.toUnsignedLong(readNextInt());
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
	 * Returns the signed value of the integer (of the specified length) at the current index.
	 * 
	 * @param len the number of bytes that the integer occupies, 1 to 8
	 * @return value of requested length, with sign bit extended, in a long
	 * @throws IOException 
	 */
	public long readNextValue(int len) throws IOException {
		long result = readValue(currentIndex, len);
		currentIndex += len;
		return result;
	}

	/**
	 * Returns the unsigned value of the integer (of the specified length) at the current index.
	 * 
	 * @param len the number of bytes that the integer occupies, 1 to 8
	 * @return unsigned value of requested length, in a long
	 * @throws IOException 
	 */
	public long readNextUnsignedValue(int len) throws IOException {
		long result = readUnsignedValue(currentIndex, len);
		currentIndex += len;
		return result;
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

	/**
	 * Reads an unsigned int32 value, and returns it as a java int (instead of a java long).
	 * <p>
	 * If the value is outside the range of 0..Integer.MAX_VALUE, an InvalidDataException is thrown.
	 * <p>
	 * Useful for reading uint32 values that are going to be used in java to allocate arrays or
	 * other similar cases where the value must be a java integer.
	 *    
	 * @return the uint32 value read from the stream, if it fits into the range [0..MAX_VALUE] 
	 * of a java integer 
	 * @throws IOException if there was an error reading
	 * @throws InvalidDataException if value can not be held in a java integer
	 */
	public int readNextUnsignedIntExact() throws IOException, InvalidDataException {
		long i = readNextUnsignedInt();
		ensureInt32u(i);
		return (int) i;
	}

	//--------------------------------------------------------------------------------------------
	// String stuff
	//--------------------------------------------------------------------------------------------
	private byte[] readUntilNullTerm(long index, int charLen) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		long curPos = index;
		for (; Long.compareUnsigned(curPos, index) >= 0; curPos += charLen) {
			// loop while we haven't wrapped the index value around to 0
			if ((long) baos.size() + charLen >= MAX_SANE_BUFFER) {
				// gracefully handle hitting the limit of the ByteArrayOutputStream before it fails
				throw new EOFException("Run-on unterminated string at 0x%s..0x%s".formatted(
					Long.toUnsignedString(index, 16), Long.toUnsignedString(curPos, 16)));
			}
			try {
				byte[] bytes = readByteArray(curPos, charLen);
				if (isNullTerm(bytes, 0, charLen)) {
					return baos.toByteArray();
				}
				baos.write(bytes);
			}
			catch (IOException e) {
				if (baos.size() == 0) {
					// failed trying to read the first byte
					throw new EOFException("Attempted to read string at 0x%s"
							.formatted(Long.toUnsignedString(index, 16)));
				}
				break; // fall thru to throw new EOF(unterminate string)
			}
		}
		// we've wrapped around the end of a 64bit address space and curPos is less than starting position
		throw new EOFException("Unterminated string at 0x%s..0x%s"
				.formatted(Long.toUnsignedString(index, 16), Long.toUnsignedString(curPos, 16)));
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
		return Byte.toUnsignedInt(readByte(index));
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
		return Short.toUnsignedInt(readShort(index));
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
		return Integer.toUnsignedLong(readInt(index));
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
	 * @param index where the value begins 
	 * @param len the number of bytes that the integer occupies, 1 to 8
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
	 * @param index where the value begins 
	 * @param len the number of bytes that the integer occupies, 1 to 8
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

	/**
	 * Reads a variable length / unknown format integer from the current position, using the
	 * supplied reader function, returning it (if it fits) as a 32 bit java integer.
	 * 
	 * @param func {@link ReaderFunction}
	 * @return signed int32
	 * @throws IOException if error reading or if the value does not fit into a 32 bit java int
	 * @throws InvalidDataException if value can not be held in a java integer
	 */
	public int readNextVarInt(ReaderFunction<Long> func) throws IOException, InvalidDataException {
		long value = func.get(this);
		ensureInt32s(value);
		return (int) value;
	}

	/**
	 * Reads a variable length / unknown format integer from the current position, using the
	 * supplied reader function, returning it (if it fits) as a 32 bit java integer.
	 * 
	 * @param func {@link InputStreamReaderFunction}
	 * @return signed int32
	 * @throws IOException if error reading or if the value does not fit into a 32 bit java int
	 * @throws InvalidDataException if value can not be held in a java integer
	 */
	public int readNextVarInt(InputStreamReaderFunction<Long> func)
			throws IOException, InvalidDataException {
		long value = func.get(getInputStream());
		ensureInt32s(value);
		return (int) value;
	}

	/**
	 * Reads a variable length / unknown format unsigned integer from the current position, using
	 * the supplied reader function, returning it (if it fits) as a 32 bit java integer.
	 * 
	 * @param func {@link ReaderFunction}
	 * @return unsigned int32
	 * @throws IOException if error reading data
	 * @throws InvalidDataException if value can not be held in a java integer
	 */
	public int readNextUnsignedVarIntExact(ReaderFunction<Long> func)
			throws IOException, InvalidDataException {
		long value = func.get(this);
		ensureInt32u(value);
		return (int) value;
	}

	/**
	 * Reads a variable length / unknown format unsigned integer from the current position, using
	 * the supplied reader function, returning it (if it fits) as a 32 bit java integer.
	 * 
	 * @param func {@link InputStreamReaderFunction}
	 * @return unsigned int32
	 * @throws IOException if error reading data
	 * @throws InvalidDataException if value can not be held in a java integer
	 */
	public int readNextUnsignedVarIntExact(InputStreamReaderFunction<Long> func)
			throws IOException, InvalidDataException {
		long value = func.get(getInputStream());
		ensureInt32u(value);
		return (int) value;
	}

	/**
	 * Reads an object from the current position, using the supplied reader function.
	 * 
	 * @param <T> type of the object that will be returned
	 * @param func {@link ReaderFunction} that will read and return an object
	 * @return new object of type T
	 * @throws IOException if error reading
	 */
	public <T> T readNext(ReaderFunction<T> func) throws IOException {
		T obj = func.get(this);
		return obj;
	}

	/**
	 * Reads an object from the current position, using the supplied reader function.
	 * 
	 * @param <T> type of the object that will be returned
	 * @param func {@link InputStreamReaderFunction} that will read and return an object
	 * @return new object of type T
	 * @throws IOException if error reading
	 */
	public <T> T readNext(InputStreamReaderFunction<T> func) throws IOException {
		T obj = func.get(getInputStream());
		return obj;
	}

	//-------------------------------------------------------------------------------------
	private static void ensureInt32u(long value) throws InvalidDataException {
		if (value < 0 || value > Integer.MAX_VALUE) {
			throw new InvalidDataException(
				"Value out of range for positive java 32 bit unsigned int: %s"
						.formatted(Long.toUnsignedString(value)));
		}
	}

	private static void ensureInt32s(long value) throws InvalidDataException {
		if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
			throw new InvalidDataException(
				"Value out of range for java 32 bit signed int: %d".formatted(value));
		}
	}

	/**
	 * Adapter between this BinaryReader and a InputStream.
	 */
	private class BinaryReaderInputStream extends InputStream {
		@Override
		public int read() throws IOException {
			if (!hasNext()) {
				return -1;
			}
			return readNextUnsignedByte();
		}
	}

}
