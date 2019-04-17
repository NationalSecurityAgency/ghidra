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
 * The Deprecated attribute is an optional fixed-length attribute in the attributes
 * table of a ClassFile, field_info or method_info structure.
 * A class, interface, method, or field may be marked using a Deprecated attribute to
 * indicate that the class, interface, method, or field has been superseded.
 * 
 * A runtime interpreter or tool that reads the class file format, such as a compiler,
 * can use this marking to advise the user that a superceded class, interface, method,
 * or field is being referred to. The presence of a Deprecated attribute does not alter
 * the semantics of a class or interface.
 * 
 * The Deprecated attribute has the following format:
 * <pre>
 * 	Deprecated_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 	}
 * </pre>
 */
public class DeprecatedAttribute extends AbstractAttributeInfo {

	public DeprecatedAttribute( BinaryReader reader ) throws IOException {
		super( reader );
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure( "Deprecated_attribute" );
		return structure;
	}

}
