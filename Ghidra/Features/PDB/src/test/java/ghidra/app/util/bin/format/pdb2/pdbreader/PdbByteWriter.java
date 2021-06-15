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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.util.LittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * This is a utility class for testing parts of the PDB Reader, which has data predominantly
 *  stored in Little Endian order in byte array buffers.  This utility is used for
 *  writing byte arrays for the purpose of testing classes that parse byte arrays for their
 *  construction/instantiation.  The class that generally reads (the reverse process) the byte
 *  arrays for the PDB Reader is the {@link PdbByteReader}, which reads in Little Endian order.
 * <P>
 * This utility class should be used as follows:
 * <OL>
 *  <LI> Instantiate a {@code ByteWriter}.</LI>
 *  <LI> Do a sequence of "put" methods.</LI>
 *  <LI> Call {@link #get()} to retrieve the byte array.</LI>
 *  <LI> Repeat process, starting with a new instantiation or call the {@link #reset()} method.</LI>
 * </OL>
 */
public class PdbByteWriter {

	private static byte[] paddingBytes = { (byte) 0xf4, (byte) 0xf3, (byte) 0xf2, (byte) 0xf1 };
	private static byte[] alignBytes = { 0x00, 0x00, 0x00, 0x00 };

	//==============================================================================================
	// Internals
	//==============================================================================================
	private byte[] scratchByteArray = new byte[8];
	private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

	//==============================================================================================
	// API
	//==============================================================================================
	public PdbByteWriter() {
		reset();
	}

	public void reset() {
		outputStream = new ByteArrayOutputStream();
		// We do not need to reset the bytes variable here.  It is created when access to it is
		// attempted with the get() method.
	}

	/**
	 * Get the number of bytes in the ByteWriter.
	 * @return The integer number of bytes in the ByteWriter.
	 */
	public int getSize() {
		return outputStream.size();
	}

	/**
	 * Method to get the resultant, desired byte array that has been populated by the "put"
	 *  methods.
	 * @return The byte[] containing the result.
	 */
	public byte[] get() {
		return outputStream.toByteArray();
	}

	/**
	 * Put the data to occupy the next byte sequence in the byte array.
	 * @param bytes The input byte array to write to the output byte array
	 */
	public void putBytes(byte[] bytes) {
		outputStream.writeBytes(bytes);
	}

	/**
	 * Put the data to occupy the next byte sequence in the byte array.
	 * @param bytes The input byte array to write to the output byte array
	 * @param num The number of bytes to write from the byte array; must be within size of input.
	 */
	public void putBytes(byte[] bytes, int num) {
		outputStream.write(bytes, 0, num);
	}

	/**
	 * Puts padding into the byte array.  Pads the buffer to a multiple of four bytes, assuming
	 *  that there were a {@code disallow} number of bytes were previously written to the buffer.
	 *  <P>
	 * This method is older than the {@link #putAlign(int)} method.  It uses specific padding
	 *  values.
	 * @param disallow The number of bytes to disallow from the calculation.
	 */
	public void putPadding(int disallow) {
		int mod = 4 * ((outputStream.size() - disallow + 3) / 4) - (outputStream.size() - disallow);
		putBytes(Arrays.copyOfRange(paddingBytes, paddingBytes.length - mod, paddingBytes.length),
			mod);
	}

	/**
	 * Puts padding into the byte array.  Pads the buffer to a multiple of four bytes, assuming
	 *  that there were a {@code disallow} number of bytes were previously written to the buffer.
	 *  <P>
	 * This method is newer than the {@link #putPadding(int)} method.  It uses 0x00 values.
	 * @param disallow The number of bytes to disallow from the calculation.
	 */
	public void putAlign(int disallow) {
		int mod = 4 * ((outputStream.size() - disallow + 3) / 4) - (outputStream.size() - disallow);
		putBytes(alignBytes, mod);
	}

	/**
	 * Put the data to occupy the next byte space in the byte array.
	 * @param value The integer value of the byte to be written.
	 */
	public void putUnsignedByte(int value) {
		scratchByteArray[0] = (byte) (value & 0xff);
		putBytes(scratchByteArray, 1);
	}

	/**
	 * Put the data to occupy the next short space in the byte array.
	 * @param value The short value of the short to be written.
	 */
	public void putShort(short value) {
		LittleEndianDataConverter.INSTANCE.putShort(scratchByteArray, value);
		putBytes(scratchByteArray, 2);
	}

	/**
	 * Put the data to occupy the next unsigned short space in the byte array.
	 * @param value The integer value of the unsigned short to be written.
	 */
	public void putUnsignedShort(int value) {
		LittleEndianDataConverter.INSTANCE.putShort(scratchByteArray, (short) (value & 0xffff));
		putBytes(scratchByteArray, 2);
	}

	/**
	 * Put the data to occupy the next integer space in the byte array.
	 * @param value The integer value of the integer to be written.
	 */
	public void putInt(int value) {
		LittleEndianDataConverter.INSTANCE.putInt(scratchByteArray, value);
		putBytes(scratchByteArray, 4);
	}

	/**
	 * Put the data to occupy the next unsigned integer space in the byte array.
	 * @param value The long value of the unsigned integer to be written.
	 */
	public void putUnsignedInt(long value) {
		LittleEndianDataConverter.INSTANCE.putInt(scratchByteArray, (int) (value & 0xffffffffffL));
		putBytes(scratchByteArray, 4);
	}

	/**
	 * Put the data to occupy the next long space in the byte array.
	 * @param value The long value of the long to be written.
	 */
	public void putLong(long value) {
		LittleEndianDataConverter.INSTANCE.putLong(scratchByteArray, value);
		putBytes(scratchByteArray, 8);
	}

	/**
	 * Put the data to occupy the next unsigned long space in the byte array.
	 * @param value The BigInteger value of the unsigned long to be written.
	 */
	public void putUnsignedLong(BigInteger value) {
		BigInteger arg = value.and(new BigInteger("ffffffffffffffff", 16));
		LittleEndianDataConverter.INSTANCE.putLong(scratchByteArray, arg.longValue());
		putBytes(scratchByteArray, 8);
	}

	/**
	 * Put the data to occupy the next Numeric field in the byte array.  For Numeric definition,
	 *  see the PdbByteReader method for reading such a field.  If value is too large for the
	 *  encoding code, the value is masked.
	 * @param value The BigInteger containing the value to be written into the Numeric field.
	 * @param code The encoding code for representing the Numeric field
	 */
	public void putNumeric(BigInteger value, int code) {
		// Drop bits. Letting value become signed too.
		BigInteger arg = value.and(new BigInteger("ffffffffffffffff", 16));
		long longValue;
		try {
			longValue = value.longValueExact();
		}
		catch (ArithmeticException e) {
			// Should not happen since we "ANDed" the value.  Fail silently
			return;
		}
		switch (code) {
			// For each case, parse bytes (to move index forward) and throw bytes away.
			//  The number of bytes parsed is based on the size of the integral type
			//  represented by subTypeIndex.
			case 0x8000: // char
				putUnsignedShort(code);
				putUnsignedByte((int) (longValue & 0xff));
				break;
			case 0x8001: // short
				putUnsignedShort(code);
				putShort((short) (longValue & 0xffff));
				break;
			case 0x8002: // unsigned short
				putUnsignedShort(code);
				putUnsignedShort((int) (longValue & 0xffff));
				break;
			case 0x8003: // 32-bit
				putUnsignedShort(code);
				putInt((int) (longValue & 0xffffffff));
				break;
			case 0x8004: // unsigned 32-bit
				putUnsignedShort(code);
				putUnsignedInt(longValue & 0xffffffff);
				break;
			case 0x8009: // 64-bit
				putUnsignedShort(code);
				putLong(longValue);
				break;
			case 0x800a: // unsigned 64-bit
				putUnsignedShort(code);
				putUnsignedLong(arg);
				break;
			default:
				return; // Fail silently.
		}
	}

	/**
	 * Put a GUID into the byte array.  The GUID is represented by the standard arguments used,
	 *  and these are accepted as arguments to this method.
	 * @param data1 An int, as first constituent piece.
	 * @param data2 A short, as second constituent piece.
	 * @param data3 A short, as third constituent piece.
	 * @param data4 A byte[8], as fourth constituent piece.
	 */
	public void putGUID(int data1, short data2, short data3, byte[] data4) {
		if (data4.length != 8) {
			String msg = "GUID invalid byte[] size... terminating";
			Msg.error(this, msg);
			throw new AssertException(msg);
		}
		putInt(data1);
		putShort(data2);
		putShort(data3);
		putBytes(data4);
	}

	/**
	 * Put the data to occupy the next byte-length-prefixed string in the byte array.
	 * @param string The String representation of the data to written.
	 */
	public void putByteLengthPrefixedString(String string) {
		int length = string.length();
		if (length > 255) {
			throw new AssertException("length > 255");
		}
		byte[] bytes = new byte[1];
		bytes[0] = (byte) length;
		putBytes(bytes);
		bytes = string.getBytes(StandardCharsets.US_ASCII);
		putBytes(bytes);
	}

	/**
	 * Put the data to occupy the next byte-length-prefixed UTF8 string in the byte array.
	 * @param string The String representation of the data to written.
	 */
	public void putByteLengthPrefixedUtf8String(String string) {
		int length = string.length();
		if (length > 255) {
			throw new AssertException("length > 255");
		}
		byte[] bytes = new byte[1];
		bytes[0] = (byte) length;
		putBytes(bytes);
		bytes = string.getBytes(StandardCharsets.UTF_8);
		putBytes(bytes);
	}

	/**
	 * Put the data to occupy the next null-terminated string in the byte array.
	 * @param string The String representation of the data to written.
	 */
	public void putNullTerminatedString(String string) {
		byte[] bytes = string.getBytes(StandardCharsets.US_ASCII);
		putBytes(bytes);
		bytes = new byte[1];
		bytes[0] = 0;
		putBytes(bytes);
	}

	/**
	 * Put the data to occupy the next null-terminated UTF8 string in the byte array.
	 * @param string The String representation of the data to written.
	 */
	public void putNullTerminatedUtf8String(String string) {
		byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
		putBytes(bytes);
		bytes = new byte[1];
		bytes[0] = 0;
		putBytes(bytes);
	}

	/**
	 * Put the data to occupy the next null-terminated wchar_t string in the byte array.
	 * @param string The String representation of the data to written.
	 */
	public void putNullTerminatedWchartString(String string) {
		byte[] bytes = string.getBytes(StandardCharsets.UTF_16);
		putBytes(bytes);
		bytes = new byte[2];
		bytes[0] = 0;
		bytes[1] = 0;
		putBytes(bytes);
	}

}
