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
 * Each value of the annotations table represents a single runtime-visible
 * annotation on a program element. 
 * <p>
 * The annotation structure has the following format:
 * <pre>
 * 	annotation {
 * 		u2 type_index;
 * 		u2 num_element_value_pairs;
 * 		{
 * 			u2 element_name_index;
 * 			element_value value;
 * 		} element_value_pair[num_element_value_pairs];
 * 	}
 * </pre>
 */
public class AnnotationJava implements StructConverter {

	private short typeIndex;
	private short numberOfElementValuePairs;
	private AnnotationElementValuePair[] elementValuePairs;

	public AnnotationJava(BinaryReader reader) throws IOException {
		typeIndex = reader.readNextShort();
		numberOfElementValuePairs = reader.readNextShort();
		elementValuePairs = new AnnotationElementValuePair[getNumberOfElementValuePairs()];
		for (int i = 0; i < getNumberOfElementValuePairs(); ++i) {
			elementValuePairs[i] = new AnnotationElementValuePair(reader);
		}
	}

	/**
	 * The value of the type_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Utf8_info structure representing a field
	 * descriptor representing the annotation type corresponding to the annotation
	 * represented by this annotation structure.
	 * @return  valid index into the constant_pool table
	 */
	public int getTypeIndex() {
		return typeIndex & 0xffff;
	}

	/**
	 * The value of the num_element_value_pairs item gives the number of
	 * element-value pairs of the annotation represented by this annotation
	 * structure.
	 * <p>
	 * Note that a maximum of 65535 element-value pairs may be contained in a single
	 * annotation.
	 * @return the number of element-value pairs of the annotation
	 */
	public int getNumberOfElementValuePairs() {
		return numberOfElementValuePairs & 0xffff;
	}

	/**
	 * Returns the element value pair table for this annotation.
	 * @return the element value pair table
	 */
	public AnnotationElementValuePair[] getElementValuePairs() {
		return elementValuePairs;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "annotation" + "|" + numberOfElementValuePairs + "|";
		StructureDataType structure = new StructureDataType(name, 0);
		structure.add(WORD, "type_index", null);
		structure.add(WORD, "num_element_value_pairs", null);
		for (int i = 0; i < elementValuePairs.length; ++i) {
			structure.add(elementValuePairs[i].toDataType(), "element_value_pair_" + i, null);
		}
		return structure;
	}

}
