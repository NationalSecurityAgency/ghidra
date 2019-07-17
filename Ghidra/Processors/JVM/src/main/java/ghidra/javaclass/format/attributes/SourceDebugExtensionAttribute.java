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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The SourceDebugExtension attribute is an optional attribute in the attributes
 * table of a ClassFile structure. There can be no more than one
 * SourceDebugExtension attribute in the attributes table of a given ClassFile
 * structure.
 * <p>
 * The SourceDebugExtension attribute has the following format:
 * <pre>
 * 	SourceDebugExtension_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u1 debug_extension[attribute_length];
 * 	}
 * </pre>
 */
public class SourceDebugExtensionAttribute extends AbstractAttributeInfo {

	private byte [] debugExtension;

	public SourceDebugExtensionAttribute( BinaryReader reader ) throws IOException {
		super( reader );

		debugExtension = reader.readNextByteArray( getAttributeLength() );
	}

	/**
	 * The debug_extension array holds extended debugging information which has
	 * no semantic effect on the Java virtual machine. The information is represented
	 * using a modified UTF-8 string with no terminating zero byte.
	 * <p>
	 * Note that the debug_extension array may denote a string longer than that which can be
	 * represented with an instance of class String.
	 * @return an array of extended debugging information
	 */
	public byte [] getDebugExtension() {
		return debugExtension;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure( "SourceDebugExtension_attribute" );
		if ( debugExtension.length > 0 ) {
			DataType array = new ArrayDataType( BYTE, debugExtension.length, BYTE.getLength() );
			structure.add( array, "debug_extension", null );
		}
		return structure;
	}

}
