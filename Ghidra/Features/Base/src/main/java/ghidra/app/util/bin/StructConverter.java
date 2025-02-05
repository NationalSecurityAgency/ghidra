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

import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.util.exception.DuplicateNameException;

/**
 * Allows a class to create a structure
 * datatype equivalent to its class members.
 * 
 * 
 */
public interface StructConverter {
	/**
	 * Reusable BYTE datatype.
	 */
	public final static DataType BYTE = ByteDataType.dataType;
	/**
	 * Reusable WORD datatype.
	 */
	public final static DataType WORD = WordDataType.dataType;
	/**
	 * Reusable DWORD datatype.
	 */
	public final static DataType DWORD = DWordDataType.dataType;
	/**
	 * Reusable QWORD datatype.
	 */
	public final static DataType QWORD = QWordDataType.dataType;
	/**
	 * Reusable ASCII datatype.
	 */
	public final static DataType ASCII = CharDataType.dataType;
	/**
	 * Reusable STRING datatype.
	 */
	public final static DataType STRING = StringDataType.dataType;
	/**
	 * Reusable UTF8 string datatype.
	 */
	public final static DataType UTF8 = StringUTF8DataType.dataType;
	/**
	 * Reusable UTF16 string datatype.
	 */
	public final static DataType UTF16 = UnicodeDataType.dataType;
	/**
	 * Reusable POINTER datatype.
	 */
	public final static DataType POINTER = PointerDataType.dataType;
	/**
	 * Reusable VOID datatype.
	 */
	public final static DataType VOID = VoidDataType.dataType;
	/**
	 * Reusable 32-bit image base offset datatype. 
	 */
	public final static DataType IBO32 = IBO32DataType.dataType;
	/**
	 * Reusable 64-bit image base offset datatype. 
	 */
	public final static DataType IBO64 = IBO64DataType.dataType;

	/**
	 * Reusable Unsigned LEB128 dynamic length data type
	 */
	public static final UnsignedLeb128DataType ULEB128 = UnsignedLeb128DataType.dataType;

	/**
	 * Reusable Signed LEB128 dynamic length data type
	 */
	public static final SignedLeb128DataType SLEB128 = SignedLeb128DataType.dataType;

	/**
	 * Returns a structure datatype representing the
	 * contents of the implementor of this interface.
	 * <p> 
	 * For example, given:
	 * <pre>
	 * class A {
	 *     int foo;
	 *     double bar;
	 * }
	 * </pre>
	 * <p>
	 * The return value should be a structure data type with two 
	 * data type components; an INT and a DOUBLE. The structure 
	 * should contain field names and, if possible,
	 * field comments.
	 * 
	 * @return returns a structure datatype representing
	 *         the implementor of this interface
	 * 
	 * @throws DuplicateNameException when a datatype of the same name already exists
	 * @throws IOException if an IO-related error occurs
	 * 
	 * @see ghidra.program.model.data.StructureDataType
	 */
	public DataType toDataType() throws DuplicateNameException, IOException;

	/**
	 * Recursively sets the given {@link Data} and its components to big/little endian
	 * 
	 * @param data The {@link Data}
	 * @param bigEndian True to set to big endian; false to set to little endian
	 * @throws Exception if there was a problem setting the endianness
	 */
	public static void setEndian(Data data, boolean bigEndian) throws Exception {
		for (int i = 0; i < data.getNumComponents(); i++) {
			Data component = data.getComponent(i);
			SettingsDefinition[] settings = component.getDataType().getSettingsDefinitions();
			for (int j = 0; j < settings.length; j++) {
				if (settings[j] instanceof EndianSettingsDefinition endianSetting) {
					endianSetting.setBigEndian(component, bigEndian);
				}
			}
			for (int j = 0; j < component.getNumComponents(); j++) {
				setEndian(component.getComponent(j), bigEndian);
			}
		}
	}
}
