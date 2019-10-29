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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The InnerClasses attribute is a variable-length attribute in the attributes table
 * of a ClassFile (?4.1) structure. If the constant pool of a class or interface C
 * contains a CONSTANT_Class_info entry which represents a class or interface that
 * is not a member of a package, then C's ClassFile structure must have exactly one
 * InnerClasses attribute in its attributes table.
 * <p>
 * The InnerClasses attribute has the following format:
 * <pre>
 * 	InnerClasses_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 number_of_classes;
 * 		{
 * 			u2 inner_class_info_index;
 * 			u2 outer_class_info_index;
 * 			u2 inner_name_index;
 * 			u2 inner_class_access_flags;
 * 		} classes[number_of_classes];
 * 	}
 * </pre>
 */
public class InnerClassesAttribute extends AbstractAttributeInfo {

	private short numberOfInnerClasses;
	private InnerClass[] innerClasses;

	public InnerClassesAttribute(BinaryReader reader) throws IOException {
		super(reader);

		numberOfInnerClasses = reader.readNextShort();
		innerClasses = new InnerClass[getNumberOfInnerClasses()];
		for (int i = 0; i < getNumberOfInnerClasses(); i++) {
			innerClasses[i] = new InnerClass(reader);
		}
	}

	/**
	 * The value of the number_of_classes item indicates the number of entries in
	 * the classes array.
	 * @return the number of entries in the classes array
	 */
	public int getNumberOfInnerClasses() {
		return numberOfInnerClasses & 0xffff;
	}

	/**
	 * Returns array of inner classes.
	 * @return array of inner classes.
	 */
	public InnerClass[] getInnerClasses() {
		return innerClasses;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure =
			getBaseStructure("InnerClasses_attribute" + "|" + numberOfInnerClasses + "|");
		structure.add(WORD, "number_of_classes", null);
		for (int i = 0; i < innerClasses.length; ++i) {
			structure.add(innerClasses[i].toDataType(), "inner_class_" + i, null);
		}

		return structure;
	}

}
