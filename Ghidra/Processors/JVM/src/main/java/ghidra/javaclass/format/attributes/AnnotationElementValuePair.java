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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * Each value of the element_value_pairs table represents a single element value
 * pair in the annotation represented by this annotation structure.
 * <p>
 * Each element_value_pairs entry contains the following two items:
 * <pre>
 * 		element_value_pair {
 * 			u2 element_name_index;
 * 			element_value value;
 * 		}
 * </pre>
 */
public class AnnotationElementValuePair implements StructConverter {

	private short elementNameIndex;
	private AnnotationElementValue value;

	public AnnotationElementValuePair(BinaryReader reader) throws IOException {
		elementNameIndex = reader.readNextShort();
		value = new AnnotationElementValue(reader);
	}

	/**
	 * The value of the element_name_index item must be a valid index
	 * into the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Utf8_info (?4.4.7) structure representing a valid
	 * field descriptor that denotes the name of the annotation type
	 * element represented by this element_value_pairs entry.
	 * @return a valid index into the constant_pool table
	 */
	public int getElementNameIndex() {
		return elementNameIndex & 0xffff;
	}

	/**
	 * The value of the value item represents the value of the element-value
	 * pair represented by this element_value_pairs entry.
	 * @return the value of the element-value pair
	 */
	public AnnotationElementValue getValue() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = new StructureDataType("element_value_pair", 0);
		structure.add(WORD, "element_name_index", null);
		structure.add(value.toDataType(), "element_value_pair", null);
		return structure;
	}
}
