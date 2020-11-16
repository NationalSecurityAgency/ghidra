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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.util.LittleEndianDataConverter;

/**
 * {@code PdbByteReader} is a utility class used for administering out portions of a byte array.
 * The requests are made with a {@code parse...} method, which interprets data, pointed to by a
 * current {@code index} into the byte array, into the type requested.
 *
 * <P>The {@code PdbByteReader} is intended for PDB (Program Data Base) / MSF (Multi-Stream File)
 * buffer processing which has data stored in a Least-Significant-Byte-First format.  Requested
 * values are read out appropriately.
 *
 * <P>When an {@code unsigned} value is requested, the value is returned in a larger integral type
 * than would normally be necessary.  This allows for java to be used (which only has signed
 * values) when  modeling a capability that was originally designed in a C/C++ world that could
 * contained an unsigned value in the smaller integral type.
 *
 * <P>Other utility methods exist for setting/getting the {@code index} or for moving the
 * {@code index} along to align or pad-out according to how a C/C++ structure would be padded in
 * memory. 
 */
public class PdbByteReader {

	//==============================================================================================
	// Internals
	//==============================================================================================
	/** byte array containing data to be parsed */
	private byte[] bytes;
	/** fixed length of the byte array */
	private int limit;
	/** current index into the byte array from which the next parse method will act */
	private int index;
	/** offset to begin alignment for methods that need to calculate alignment */
	private int alignMarker;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor for a PdbByteReader. Takes byte array of data to be read in particular
	 *  increments and formats.
	 * @param bytes byte[] of data to be read/processed.
	 */
	public PdbByteReader(byte[] bytes) {
		this.bytes = bytes;
		limit = (bytes == null) ? 0 : bytes.length;
		index = 0;
		alignMarker = 0;
	}

	/**
	 * Resets the index of the PdbByteReader back to zero.
	 */
	public void reset() {
		index = 0;
		alignMarker = 0;
	}

	/**
	 * Returns the number of bytes remaining in the PdbByteReader.
	 * @return The number of bytes remaining.
	 */
	public int numRemaining() {
		return limit - index;
	}

	/**
	 * Returns the current index of the PdbByteReader.
	 * @return The current index.
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * Returns the limit of the PdbByteReader.
	 * @return The index limit.
	 */
	public int getLimit() {
		return limit;
	}

	/**
	 * Sets the index to the value specified.  Silently fails when outside of array.
	 * @param index The to set to the index.
	 */
	public void setIndex(int index) {
		if (index >= 0 && index < limit) {
			this.index = index;
		}
	}

	/**
	 * Returns true if there are more bytes remaining in the PdbByteReader.
	 * @return True if more bytes remain.
	 */
	public boolean hasMore() {
		return (index < limit);
	}

	/**
	 * Returns true if there are more bytes remaining in the PdbByteReader which are non-pad bytes.
	 * @return True if more non-pad bytes remain.
	 */
	public boolean hasMoreNonPad() {
		if (!hasMore()) {
			return false;
		}
		return (bytes[index] & 0xff) <= 0xf0;
	}

	/**
	 * Parses a single byte (unsigned char) of data from the PdbByteReader and returns its
	 *  positive integer value.
	 * @return The positive integer value of the parsed byte.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public int parseUnsignedByteVal() throws PdbException {
		checkLimit(1);
		return bytes[index++] & 0xff;
	}

	/**
	 * Parses and returns in an int, the specified-size integer type value (16 or 32).
	 * @param size the size in bits of the integer.
	 * @return the value parsed.
	 * @throws PdbException upon unhandled size specified in arguments.
	 */
	public int parseVarSizedInt(int size) throws PdbException {
		switch (size) {
			case 16:
				return parseShort();
			case 32:
				return parseInt();
		}
		throw new PdbException("Bad int size");
	}

	/**
	 * Parses and returns in an unsigned int, the specified-size unsigned integer type value
	 * (8 or 16).
	 * @param size the size in bits of the unsigned integer.
	 * @return the value parsed.
	 * @throws PdbException upon unhandled size specified in arguments.
	 */
	public int parseSmallVarSizedUInt(int size) throws PdbException {
		switch (size) {
			case 8:
				return parseUnsignedByteVal();
			case 16:
				return parseUnsignedShortVal();
		}
		throw new PdbException("Bad int size");
	}

	/**
	 * Parses and returns in an unsigned int, the specified-size unsigned integer type value
	 * (8, 16, or 32).
	 * @param size the size in bits of the unsigned integer.
	 * @return the value parsed.
	 * @throws PdbException upon unhandled size specified in arguments.
	 */
	public long parseVarSizedUInt(int size) throws PdbException {
		switch (size) {
			case 8:
				return parseUnsignedByteVal();
			case 16:
				return parseUnsignedShortVal();
			case 32:
				return parseUnsignedIntVal();
		}
		throw new PdbException("Bad int size");
	}

	/**
	 * Parses and returns in an int, which that is intended to be used as an <B>offset</B>, using
	 * the specified-size integer type value  (16 or 32).  When 16, and <B>unsigned</B> short is
	 * parsed; when 32, a <B>signed</B> int is parsed.
	 * @param size the size in bits of the integer.
	 * @return the value parsed.
	 * @throws PdbException upon unhandled size specified in arguments.
	 */
	public long parseVarSizedOffset(int size) throws PdbException {
		switch (size) {
			case 16:
				return parseUnsignedShortVal();
			case 32:
				return parseUnsignedIntVal();
		}
		throw new PdbException("Bad offset size");
	}

	/**
	 * Parses and returns in an int, which that is intended to be used as a <B>count</B>, using the
	 * specified-size integer type value  (16 or 32).  When 16, and <B>unsigned</B> short is
	 * parsed; when 32, a <B>signed</B> int is parsed.
	 * @param size the size in bits of the integer.
	 * @return the value parsed.
	 * @throws PdbException upon unhandled size specified in arguments.
	 */
	public int parseVarSizedCount(int size) throws PdbException {
		switch (size) {
			case 16:
				return parseUnsignedShortVal();
			case 32:
				return parseInt();
		}
		throw new PdbException("Bad count size");
	}

	/**
	 * Parses and returns a short from the PdbByteReader.
	 * @return The short parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public short parseShort() throws PdbException {
		checkLimit(2);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + 2);
		index += 2;
		return LittleEndianDataConverter.INSTANCE.getShort(selectedBytes);
	}

	/**
	 * Parses an unsigned short from the PdbByteReader and returns its positive integer value.
	 * @return The positive integer value of the parsed unsigned short.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public int parseUnsignedShortVal() throws PdbException {
		checkLimit(2);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + 2);
		// Resize with padding because of possibility of unsigned overflow into short.
		selectedBytes = Arrays.copyOf(selectedBytes, 4);
		index += 2;
		return LittleEndianDataConverter.INSTANCE.getInt(selectedBytes);
	}

	/**
	 * Parses and returns an integer from the PdbByteReader.
	 * @return The integer parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public int parseInt() throws PdbException {
		checkLimit(4);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + 4);
		index += 4;
		return LittleEndianDataConverter.INSTANCE.getInt(selectedBytes);
	}

	/**
	 * Parses an unsigned int from the PdbByteReader and returns its positive long value.
	 * @return The positive long value of the parsed unsigned int.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public long parseUnsignedIntVal() throws PdbException {
		checkLimit(4);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + 4);
		selectedBytes = Arrays.copyOf(selectedBytes, 8);
		index += 4;
		return LittleEndianDataConverter.INSTANCE.getLong(selectedBytes);
	}

	/**
	 * Parses and returns a (64-bit) long from the PdbByteReader.
	 * @return The integer parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public long parseLong() throws PdbException {
		checkLimit(8);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + 8);
		index += 8;
		return LittleEndianDataConverter.INSTANCE.getLong(selectedBytes);
	}

	/**
	 * Parses an (64-bit) unsigned long from the PdbByteReader and returns its positive
	 *  BigInteger value.
	 * @return The positive long value of the parsed unsigned int.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public BigInteger parseUnsignedLongVal() throws PdbException {
		checkLimit(8);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + 8);
		selectedBytes = Arrays.copyOf(selectedBytes, 8);
		index += 8;
		return LittleEndianDataConverter.INSTANCE.getBigInteger(selectedBytes, 8, false);
	}

	/**
	 * Parses and returns a short-valued-length-prefixed byte array from the PdbByteReader (not
	 *  including the 2 bytes of the short-valued-length).  An unsigned short is first parsed.
	 *  This value tells the number of bytes to be read and returned as a byte[].
	 * @return The byte[] parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public byte[] parseShortLengthPrefixedByteArray() throws PdbException {
		checkLimit(2);
		int length = parseUnsignedShortVal();
		checkLimit(length);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + length);
		index += length;
		return selectedBytes;
	}

	/**
	 * Returns the remaining bytes in the PdbByteReader as a byte array.
	 * @return The byte[] containing the remaining bytes.
	 */
	public byte[] parseBytesRemaining() {
		int remaining = limit - index;
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + remaining);
		index += remaining;
		return selectedBytes;
	}

	/**
	 * Extracts and returns a byte array of bytes from the PdbByteReader, the number of which
	 *  is specified byte the parameter.
	 * @param num The number of bytes to extract and return.
	 * @return The byte[] containing the number of bytes requested.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public byte[] parseBytes(int num) throws PdbException {
		checkLimit(num);
		byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + num);
		index += num;
		return selectedBytes;
	}

	/**
	 * Returns a sub-PdbByteReader starting at the current index location and limited to the
	 *  length. The parent PdbByteReader index gets moved forward by length.
	 * @param length The length of the sub-PdbByteReader.
	 * @return The sub-PdbByteReader.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public PdbByteReader getSubPdbByteReader(int length) throws PdbException {
		return new PdbByteReader(parseBytes(length));
	}

	/**
	 * Parses an GUID from the PdbByteReader.
	 * @return The GUID parsed.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public GUID parseGUID() throws PdbException {
		checkLimit(16);
		int data1 = parseInt();
		short data2 = parseShort();
		short data3 = parseShort();
		byte[] data4 = parseBytes(8);
		return new GUID(data1, data2, data3, data4);
	}

	/**
	 * Parses a string, as indicated by the {@link StringParseType}, from the PdbByteReader and
	 * returns it.  Where needed, uses one of the String encoding options as retained in the
	 * associated {@link PdbReaderOptions}.
	 * @param pdb the {@link AbstractPdb} for which the parsing is taking place.
	 * @param stType the {@link StringParseType} to use for parsing.
	 * @return the resultant {@link String}.
	 * @throws PdbException upon unhandled {@link StringParseType}.
	 */
	public String parseString(AbstractPdb pdb, StringParseType stType) throws PdbException {
		switch (stType) {
			case StringNt:
				return parseNullTerminatedString(pdb.getPdbReaderOptions().getOneByteCharset());
			case StringSt:
				return parseByteLengthPrefixedString(pdb.getPdbReaderOptions().getOneByteCharset());
			case StringUtf8St:
				return parseByteLengthPrefixedUtf8String();
			case StringUtf8Nt:
				return parseNullTerminatedUtf8String();
			case StringWcharNt:
				return parseNullTerminatedWcharString(
					pdb.getPdbReaderOptions().getTwoByteCharset());
			default:
				throw new PdbException("Bad string type");
		}
	}

	/**
	 * Parses and returns a byte-valued-length-prefixed String from the PdbByteReader.  The
	 *  string length is determined by the first byte of data (not returned)--there is not a null
	 *  terminator in the source bytes.  This number of bytes is extracted and converted to a
	 *  String and returned.
	 * @param charset the {@link Charset} to be used for parsing the {@link String}.
	 * @return The String containing the bytes (excluding the byte containing the length).
	 * @throws PdbException upon error parsing string.
	 */
	public String parseByteLengthPrefixedString(Charset charset) throws PdbException {
		int length = parseUnsignedByteVal();
		if (length == 0) {
			return "";
		}
		int offset = index;
		index += length;
		try {
			return new String(bytes, offset, length, charset);
		}
		catch (IndexOutOfBoundsException e) {
			throw new PdbException("Error parsing String: " + e.toString());
		}
	}

	/**
	 * Parses and returns a byte-valued-length-prefixed UTF8 String from the PdbByteReader.  The
	 *  string length is determined by the first byte of data (not returned)--there is not null
	 *  terminator in the source bytes.  This number of bytes is extracted and converted to a
	 *  {@link String} and returned.
	 * @return The String containing the bytes (excluding the byte containing the length).
	 * @throws PdbException upon error parsing string.
	 */
	public String parseByteLengthPrefixedUtf8String() throws PdbException {
		int length = parseUnsignedByteVal();
		if (length == 0) {
			return "";
		}
		int offset = index;
		index += length;
		try {
			return new String(bytes, offset, length, StandardCharsets.UTF_8);
		}
		catch (IndexOutOfBoundsException e) {
			throw new PdbException("Error parsing String: " + e.toString());
		}
	}

	/**
	 * Parses a null-terminated string from the PdbByteReader and returns the {@link String} (minus
	 *  the terminating null character).  If no null, returns up to end of PdbByteReader.
	 * @param charset the {@link Charset} to be used for parsing the {@link String}.
	 * @return The String parsed.
	 */
	public String parseNullTerminatedString(Charset charset) {
		int offset = index;
		int width = 1;
		int end = findNullTerminatorIndex(width);
		index = end + width;
		if (end == offset) {
			return "";
		}
		return new String(bytes, offset, end - offset, charset);
	}

	/**
	 * Parses a null-terminated UTF-8 string from the PdbByteReader and returns the String (minus
	 *  the terminating null character).  If no null, returns up to end of PdbByteReader.
	 * @return The String parsed.
	 */
	public String parseNullTerminatedUtf8String() {
		int offset = index;
		int width = 1;
		int end = findNullTerminatorIndex(width);
		index = end + width;
		if (end == offset) {
			return "";
		}
		return new String(bytes, offset, end - offset, StandardCharsets.UTF_8);
	}

	/**
	 * Parses a null-terminated wchar_t string from the PdbByteReader and returns the String (minus
	 *  the terminating null character).  If no null, returns up to end of PdbByteReader.
	 * @param charset the {@link Charset} to be used for parsing the {@link String}.
	 * @return The String parsed.
	 */
	public String parseNullTerminatedWcharString(Charset charset) {
		int offset = index;
		int width = 2;
		int end = findNullTerminatorIndex(width);
		index = end + width;
		if (end == offset) {
			return "";
		}
		return new String(bytes, offset, end - offset, charset);
	}

	/**
	 * Stores the current index value as a marker for performing alignment.  The {@link #align4()}
	 * method calculates alignment based on this marker.
	 * @param alignMarkerIn Offset to begin alignment calculations.
	 */
	public void markAlign(int alignMarkerIn) {
		this.alignMarker = alignMarkerIn;
	}

	/**
	 * Moves the index of the PdbByteReader to align on a 4-byte boundary of the initializing
	 *  byte array, modified by an alignment modifier passed in by {@link #markAlign(int)}.
	 * @return The number added to the index.
	 */
	public int align4() {
		int excess = (index - alignMarker) & 0x03;
		int pad = (excess == 0) ? 0 : 4 - excess;
		index += pad;
		return pad;
	}

	/**
	 * This is a specialized method for PDB that should only be used when the Subject Matter
	 *  Expert know it is appropriate to use.  It looks for and removes padding bytes that are
	 *  indications of and take the place of alignment padding.
	 * @return The number of padding bytes removed (also the increase in index).
	 */
	public int skipPadding() {
		int initialIndex = index;
		while ((index < limit) && (bytes[index] & 0xf0) == 0xf0) {
			index++;
		}
		return index - initialIndex;
	}

	/**
	 * This method skips the number of bytes specified.  Does not skip beyond the end.
	 * @param num The number of bytes to skip.
	 */
	public void skip(int num) {
		if (num > (limit - index)) {
			index = limit;
		}
		else {
			index += num;
		}
	}

	/**
	 * Debug method used the dump bytes of the PdbByteReader to String in a pretty format to a
	 * String.  Includes header of internal values.
	 * @return String of data dumped.
	 */
	public String dump() {
		return dump(0, limit);
	}

	/**
	 * Debug method used the dump a specified number of bytes of the PdbByteReader in a pretty
	 * format to a String, starting at the current index.  Includes header of internal values.
	 * @param max The max number of bytes to output.
	 * @return String of data dumped.
	 */
	public String dump(int max) {
		return dump(index, index + max);
	}

	/**
	 * Debug method used the dump a specified number of bytes of the PdbByteReader in a pretty
	 * format, starting at the first parameter and continuing to the one less than the last
	 * parameter.  First dumped are the number of bytes in the PdbByteReader, followed by the
	 * current index, followed by the number of first and last parameter values, followed byte
	 * the bytes specified ((or up to end of buffer if it comes first).
	 * @param first Index of first byte to output
	 * @param last Index of last byte to output (limited by end of the buffer)
	 * @return String containing the pretty output format
	 */
	public String dump(int first, int last) {
		StringBuilder builder = new StringBuilder();
		last = last > limit ? limit : last;
		builder.append("limit: ");
		builder.append(limit);
		builder.append("\nindex: ");
		builder.append(index);
		builder.append("\nfirst: ");
		builder.append(first);
		builder.append("\nlast: ");
		builder.append(last);
		builder.append(dumpBytes(first, last));
		return builder.toString();
	}

	/**
	 * Debug method used the dump bytes of the PdbByteReader to String in a pretty format to a
	 * String.
	 * @return String of data dumped.
	 */
	public String dumpBytes() {
		return dumpBytes(0, limit);
	}

	/**
	 * Debug method used the dump a specified number of bytes of the PdbByteReader in a pretty
	 * format to a String, starting at the current index.
	 * @param max The max number of bytes to output.
	 * @return String of data dumped.
	 */
	public String dumpBytes(int max) {
		return dumpBytes(index, index + max);
	}

	/**
	 * Debug method used the dump a specified number of bytes of the PdbByteReader in a pretty
	 * format, starting at the first parameter and continuing to the one less than the last
	 * parameter.  Only the bytes are dumped.
	 * @param first Index of first byte to output
	 * @param last Index of last byte to output (limited by end of the buffer)
	 * @return String containing the pretty output format
	 */
	public String dumpBytes(int first, int last) {
		if (first > last || first > limit) {
			return "";
		}
		StringBuilder builder = new StringBuilder();
		last = last > limit ? limit : last;
		for (int i = first; i < last;) {
			builder.append(String.format("\n%06x", i));
			for (int j = 0; (j < 16) && (i < last); j++, i++) {
				builder.append(String.format(" %02x", bytes[i]));
			}
		}
		return builder.toString();
	}

	//==============================================================================================
	// Private Methods
	//==============================================================================================
	/**
	 * Checks if {@code numNeeded} bytes is available between {@code index} and {@code limit}.
	 *  Throws PdbException if space is not available.  The {@code numNeeded} value is the amount
	 *  that the caller intends to increment {@code index} by, and the resultant value is allowed
	 *  to hit {@code limit}, but not exceed {@code limit}, as the {@code index} value is that of
	 *  what would be the next byte to read, if one was going to read again.
	 * @param numNeeded The number of bytes for the check availability.
	 * @throws PdbException Upon {@code numNeeded} bytes not available in the reader between
	 *  {@code index} and {@code limit}.
	 */
	private void checkLimit(int numNeeded) throws PdbException {
		if (numNeeded < 0) {
			throw new PdbException("Illegal negative.");
		}
		if (Integer.MAX_VALUE - index < numNeeded) {
			throw new PdbException("Needed data beyond max.");
		}
		if (index + numNeeded > limit) {
			throw new PdbException("Needed data is not available.");
		}
	}

	/**
	 * Returns the index of the first character of the null terminator of any width.
	 * @param width The width of the terminator.
	 * @return The index of the first character of the terminator.
	 */
	private int findNullTerminatorIndex(int width) {
		int count = 0;
		int finderIndex = index;
		while (finderIndex < limit) {
			if (bytes[finderIndex++] == 0x00) {
				if (++count == width) {
					return finderIndex - width;
				}
			}
			else {
				count = 0;
			}
		}
		return limit;
	}

}
