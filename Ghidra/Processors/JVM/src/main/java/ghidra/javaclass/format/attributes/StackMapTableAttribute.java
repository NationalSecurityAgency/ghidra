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
 * The StackMapTable attribute is a variable-length attribute in the attributes
 * table of a Code attribute. This attribute is used during the process of
 * verification by typechecking. A method's Code attribute may have at most
 * one StackMapTable attribute.
 * <p>
 * A StackMapTable attribute consists of zero or more stack map frames. Each
 * stack map frame specifies (either explicitly or implicitly) a bytecode offset, the
 * verification types for the local variables, and the verification types for
 * the operand stack.
 * <p>
 * The type checker deals with and manipulates the expected types of a method's local
 * variables and operand stack. Throughout this section, a location refers to either a
 * single local variable or to a single operand stack entry.
 * <p>
 * We will use the terms stack map frame and type state interchangeably to describe
 * a mapping from locations in the operand stack and local variables of a method
 * to verification types. We will usually use the term stack map frame when such a
 * mapping is provided in the class file, and the term type state when the mapping
 * is used by the type checker.
 * <p>
 * In a class file whose version number is greater than or equal to 50.0, if a method's
 * Code attribute does not have a StackMapTable attribute, it has an implicit stack
 * map attribute. This implicit stack map attribute is equivalent to a StackMapTable
 * attribute with number_of_entries equal to zero.
 * <p>
 * The StackMapTable attribute has the following format:
 * <pre.
 * 	StackMapTable_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 number_of_entries;
 * 		stack_map_frame entries[number_of_entries];
 * 	}
 * </pre>
 */
public class StackMapTableAttribute extends AbstractAttributeInfo {

//	private short numberOfEntries;
//	private StackMapFrame [] entries;
	private byte [] infoBytes;

	public StackMapTableAttribute( BinaryReader reader ) throws IOException {
		super( reader );

//		numberOfEntries = reader.readNextShort();

//		entries = new StackMapFrame[ numberOfEntries ];
//		for ( int i = 0 ; i < numberOfEntries ; i++ ) {
//			entries[ i ] = new StackMapFrame( reader );
//		}
		infoBytes = reader.readNextByteArray( getAttributeLength() );
	}

//	public short getNumberOfEntries() {
//		return numberOfEntries;
//	}
//
//	public StackMapFrame[] getEntries() {
//		return entries;
//	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
//		String name = "StackMapTable_attribute_" + entries;
//		StructureDataType structure = getBaseStructure( name );
//		structure.add( WORD, "number_of_entries", null );
//		for ( int i = 0 ; i < entries.length ; ++i ) {
//			structure.add( entries[ i ].toDataType(), "entries_" + i, null );
//		}
//		return structure;
		StructureDataType structure = getBaseStructure( "StackMapTable_attribute" );
		if ( infoBytes.length > 0 ) {
			DataType array = new ArrayDataType( BYTE, infoBytes.length, BYTE.getLength() );
			structure.add( array, "info", null );
		}
		return structure;
	}

}
