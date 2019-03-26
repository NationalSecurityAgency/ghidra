/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.javaclass.format.attributes;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The Synthetic attribute is a fixed-length attribute in the attributes table of a
 * ClassFile, field_info or method_info structure. 
 * A class member that does not appear in the source code must be marked using a Synthetic
 * attribute, or else it must have its ACC_SYNTHETIC flag set. The only exceptions
 * to this requirement are compiler-generated methods which are not considered
 * implementation artifacts, namely the instance initialization method representing a
 * default constructor of the Java programming language, the class initialization
 * method, and the Enum.values() and Enum.valueOf() methods.
 * <p>
 * The value of the attribute_name_index item must be a valid index into
 * the constant_pool table. The constant_pool entry at that index must be a
 * CONSTANT_Utf8_info structure representing the string "Synthetic".
 */
public class SyntheticAttribute extends AbstractAttributeInfo {

	public SyntheticAttribute( BinaryReader reader ) throws IOException {
		super( reader );
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure( "Synthetic_attribute" );
		return structure;
	}

}
