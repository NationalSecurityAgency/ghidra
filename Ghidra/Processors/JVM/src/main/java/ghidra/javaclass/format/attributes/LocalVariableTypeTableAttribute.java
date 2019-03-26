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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The LocalVariableTypeTable attribute is an optional variable-length attribute in
 * the attributes table of a Code attribute. It may be used by debuggers to
 * determine the value of a given local variable during the execution of a method.
 * <p>
 * If LocalVariableTypeTable attributes are present in the attributes table of a
 * given Code attribute, then they may appear in any order. There may be no more than
 * one LocalVariableTypeTable attribute per local variable in the Code attribute.
 * <p>
 * The LocalVariableTypeTable attribute differs from the LocalVariableTable
 * attribute in that it provides signature information rather than descriptor information.
 * This difference is only significant for variables whose type is a generic reference
 * type. Such variables will appear in both tables, while variables of other types will
 * appear only in LocalVariableTable.
 * <p>
 * The LocalVariableTypeTable attribute has the following format:
 * <pre>
 * 	LocalVariableTypeTable_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 local_variable_type_table_length;
 * 		{
 * 			u2 start_pc;
 * 			u2 length;
 * 			u2 name_index;
 * 			u2 signature_index;
 * 			u2 index;
 * 		} local_variable_type_table[local_variable_type_table_length];
 * 	}
 * </pre>
 */
public class LocalVariableTypeTableAttribute extends AbstractAttributeInfo {

	private byte [] infoBytes;

	public LocalVariableTypeTableAttribute( BinaryReader reader ) throws IOException {
		super( reader );

		infoBytes = reader.readNextByteArray( getAttributeLength() );
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure( "LocalVariableTypeTable_attribute" );
		if ( infoBytes.length > 0 ) {
			DataType array = new ArrayDataType( BYTE, infoBytes.length, BYTE.getLength() );
			structure.add( array, "info", null );
		}
		return structure;
	}

}
