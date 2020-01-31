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
package ghidra.app.util.datatype.microsoft;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.Conv;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.NumericUtilities;

/**
 * GUIDs identify objects such as interfaces, manager entry-point vectors (EPVs), 
 * and class objects. A GUID is a 128-bit value consisting of one group 
 * of 8 hexadecimal digits, followed by three groups of 4 hexadecimal 
 * digits each, followed by one group of 12 hexadecimal digits. The 
 * following example shows the groupings of hexadecimal digits in a GUID.
 * <br>
 * <code>6B29FC40-CA47-1067-B31D-00DD010662DA</code>
 * <br>
 * <pre>
 * typedef struct _GUID {
 * 		DWORD Data1;
 * 		WORD Data2;
 * 		WORD Data3;
 * 		BYTE Data4[8];
 * } GUID;
 * </pre>
 * Data1 - Specifies the first 8 hexadecimal digits of the GUID.<br> 
 * Data2 - Specifies the first group of 4 hexadecimal digits.<br>
 * Data3 - Specifies the second group of 4 hexadecimal digits.<br>
 * Data4 - Array of 8 bytes.
 *         The first 2 bytes contain the third group of 4 hexadecimal digits.
 *         The remaining 6 bytes contain the final 12 hexadecimal digits.<br> 
 */
public class GUID {
	public final static int SIZEOF = 16;

	private int data1;
	private short data2;
	private short data3;
	private byte[] data4 = new byte[8];

	/**
	 * Creates a GUID object using the GUID string form.
	 * @param guidString - "6B29FC40-CA47-1067-B31D-00DD010662DA"
	 * @throws IllegalArgumentException if string does not represent a valid GUID
	 */
	public GUID(String guidString) {
		if (guidString.length() != 36) {
			throw new IllegalArgumentException("Invalid GUID string.");
		}
		int pos = guidString.indexOf('-');
		if (pos == -1) {
			throw new IllegalArgumentException("Invalid GUID string.");
		}
		data1 = (int) NumericUtilities.parseHexLong(guidString.substring(0, pos));

		guidString = guidString.substring(pos + 1);
		pos = guidString.indexOf('-');
		if (pos == -1) {
			throw new IllegalArgumentException("Invalid GUID string.");
		}
		data2 = (short) Integer.parseInt(guidString.substring(0, pos), 16);

		guidString = guidString.substring(pos + 1);
		pos = guidString.indexOf('-');
		if (pos == -1) {
			throw new IllegalArgumentException("Invalid GUID string.");
		}
		data3 = (short) Integer.parseInt(guidString.substring(0, pos), 16);

		guidString = guidString.substring(pos + 1);
		pos = guidString.indexOf('-');
		if (pos == -1) {
			throw new IllegalArgumentException("Invalid GUID string.");
		}
		int value = Integer.parseInt(guidString.substring(0, pos), 16);
		data4[0] = (byte) (value >> 8);
		data4[1] = (byte) (value & 0xff);

		guidString = guidString.substring(pos + 1);
		data4[2] = (byte) Integer.parseInt(guidString.substring(0, 2), 16);
		guidString = guidString.substring(2);
		data4[3] = (byte) Integer.parseInt(guidString.substring(0, 2), 16);
		guidString = guidString.substring(2);
		data4[4] = (byte) Integer.parseInt(guidString.substring(0, 2), 16);
		guidString = guidString.substring(2);
		data4[5] = (byte) Integer.parseInt(guidString.substring(0, 2), 16);
		guidString = guidString.substring(2);
		data4[6] = (byte) Integer.parseInt(guidString.substring(0, 2), 16);
		guidString = guidString.substring(2);
		data4[7] = (byte) Integer.parseInt(guidString.substring(0, 2), 16);
	}

	/**
	 * Constructs a GUID using the constitute pieces.
	 */
	public GUID(int data1, short data2, short data3, byte[] data4) {
		this.data1 = data1;
		this.data2 = data2;
		this.data3 = data3;
		this.data4 = data4;
	}

	/**
	 * Reads a GUID from the given binary reader.
	 * @param reader the binary reader to read the GUID
	 * @throws IOException if an I/O error occurs while reading the GUID
	 */
	public GUID(BinaryReader reader) throws IOException {
		data1 = reader.readNextInt();
		data2 = reader.readNextShort();
		data3 = reader.readNextShort();
		data4 = reader.readNextByteArray(8);
	}

	/**
	 * Reads a GUID from the given memory buffer.
	 * @param buf the memory buffer to read the GUID
	 * @throws MemoryAccessException if an error occurs while reading the GUID
	 */
	public GUID(MemBuffer buf) throws MemoryAccessException {
		byte[] data1bytes = new byte[4];
		byte[] data2bytes = new byte[2];
		byte[] data3bytes = new byte[2];
		byte[] data4bytes = new byte[8];

		int offset = 0;

		for (int i = 0; i < data1bytes.length; ++i) {
			data1bytes[i] = buf.getByte(offset++);
		}
		for (int i = 0; i < data2bytes.length; ++i) {
			data2bytes[i] = buf.getByte(offset++);
		}
		for (int i = 0; i < data3bytes.length; ++i) {
			data3bytes[i] = buf.getByte(offset++);
		}
		for (int i = 0; i < data4bytes.length; ++i) {
			data4bytes[i] = buf.getByte(offset++);
		}

		DataConverter dc = getDataConverter(buf);
		data1 = dc.getInt(data1bytes);
		data2 = dc.getShort(data2bytes);
		data3 = dc.getShort(data3bytes);
		data4 = data4bytes;
	}

	private DataConverter getDataConverter(MemBuffer buf) {
		return DataConverter.getInstance(buf.isBigEndian());
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append(Conv.toHexString(data1));
		buffer.append("-");
		buffer.append(Conv.toHexString(data2));
		buffer.append("-");
		buffer.append(Conv.toHexString(data3));
		buffer.append("-");
		buffer.append(Conv.toHexString(data4[0]));
		buffer.append(Conv.toHexString(data4[1]));
		buffer.append("-");
		buffer.append(Conv.toHexString(data4[2]));
		buffer.append(Conv.toHexString(data4[3]));
		buffer.append(Conv.toHexString(data4[4]));
		buffer.append(Conv.toHexString(data4[5]));
		buffer.append(Conv.toHexString(data4[6]));
		buffer.append(Conv.toHexString(data4[7]));
		return buffer.toString();
	}

	/**
	 * Specifies the first 8 hexadecimal digits of the GUID.
	 * @return
	 */
	public int getData1() {
		return data1;
	}

	/**
	 * Specifies the first group of 4 hexadecimal digits.
	 * @return
	 */
	public short getData2() {
		return data2;
	}

	/**
	 * Specifies the second group of 4 hexadecimal digits.
	 * @return
	 */
	public short getData3() {
		return data3;
	}

	/**
	 * Array of 8 bytes.
	 * The first 2 bytes contain the third group of 4 hexadecimal digits.
	 * The remaining 6 bytes contain the final 12 hexadecimal digits.
	 * @return
	 */
	public byte[] getData4() {
		return data4;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + data1;
		result = prime * result + data2;
		result = prime * result + data3;
		result = prime * result + Arrays.hashCode(data4);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GUID other = (GUID) obj;
		if (data1 != other.data1) {
			return false;
		}
		if (data2 != other.data2) {
			return false;
		}
		if (data3 != other.data3) {
			return false;
		}
		if (!Arrays.equals(data4, other.data4)) {
			return false;
		}
		return true;
	}
}
