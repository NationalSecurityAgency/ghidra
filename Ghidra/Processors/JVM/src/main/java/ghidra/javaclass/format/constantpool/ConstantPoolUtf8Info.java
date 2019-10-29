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
package ghidra.javaclass.format.constantpool;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The CONSTANT_Utf8_info structure is used to represent constant string values:
 * <pre>
 * 	CONSTANT_Utf8_info {
 * 		u1 tag;
 * 		u2 length;
 * 		u1 bytes[length];
 * 	}
 * </pre>
 * <p>
 * String content is encoded in modified UTF-8. Modified UTF-8 strings are encoded
 * so that code point sequences that contain only non-null ASCII characters can be
 * represented using only 1 byte per code point, but all code points in the Unicode
 * codespace can be represented.
 */
public class ConstantPoolUtf8Info extends AbstractConstantPoolInfoJava {

	private short length;
	private byte[] bytes;

	public ConstantPoolUtf8Info(BinaryReader reader) throws IOException {
		super(reader);
		length = reader.readNextShort();
		bytes = reader.readNextByteArray(getLength());
	}

	/**
	 * The value of the length item gives the number of bytes in the bytes array
	 * (not the length of the resulting string). The strings in the CONSTANT_Utf8_info
	 * structure are not null-terminated.
	 * @return the number of bytes in the bytes array
	 */
	public int getLength() {
		return length & 0xffff;
	}

	/**
	 * The bytes array contains the bytes of the string. 
	 * No byte may have the value (byte)0 or lie in the 
	 * range (byte)0xf0 - (byte)0xff.
	 * @return the bytes of the string
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * TODO
	 * Returns the byte array translated into a string.
	 * @return the byte array translated into a string
	 */
	public String getString() {
		return new String(bytes);
	}

	@Override
	public String toString() {
		return getString();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Utf8_info" + "|" + length + "|";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "length", null);
		if (length > 0) {
			structure.add(UTF8, length, "data", null);
		}
		return structure;
	}
}
