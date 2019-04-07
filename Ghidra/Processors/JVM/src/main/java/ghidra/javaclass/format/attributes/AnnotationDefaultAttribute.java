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
 * The AnnotationDefault attribute is a variable-length attribute in the attributes
 * table of certain method_info structures, namely those representing elements
 * of annotation types. The AnnotationDefault attribute records the default value
 * for the element represented by the method_info structure.
 * <b>
 * Each method_info structure representing an element of an annotation type may
 * contain at most one AnnotationDefault attribute. The Java virtual machine must
 * make this default value available so it can be applied by appropriate reflective APIs.
 * <b>
 * The AnnotationDefault attribute has the following format:
 * <pre>
 * 	AnnotationDefault_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		element_value default_value;
 * 	}
 * </pre>
 */
public class AnnotationDefaultAttribute extends AbstractAttributeInfo {

	private AnnotationElementValue defaultValue;

	public AnnotationDefaultAttribute( BinaryReader reader ) throws IOException {
		super( reader );

		defaultValue = new AnnotationElementValue( reader );
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure( "AnnotationDefault_attribute" );
		structure.add( defaultValue.toDataType(), "default_value", null );
		return structure;
	}

}
