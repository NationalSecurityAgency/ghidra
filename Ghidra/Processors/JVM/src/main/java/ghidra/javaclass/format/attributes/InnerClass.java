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
 * Each classes array entry contains the following four items:
 * <pre>
 * 	InnerClass {
 * 		u2 inner_class_info_index;
 * 		u2 outer_class_info_index;
 * 		u2 inner_name_index;
 * 		u2 inner_class_access_flags;
 * 	}
 * </pre>
 */
public class InnerClass implements StructConverter {

	private short innerClassInfoIndex;
	private short outerClassInfoIndex;
	private short innerNameIndex;
	private short innerClassAccessFlags;

	public InnerClass(BinaryReader reader) throws IOException {
		innerClassInfoIndex = reader.readNextShort();
		outerClassInfoIndex = reader.readNextShort();
		innerNameIndex = reader.readNextShort();
		innerClassAccessFlags = reader.readNextShort();
	}

	/**
	 * The value of the inner_class_info_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index must be
	 * a CONSTANT_Class_info structure representing C. The remaining
	 * items in the classes array entry give information about C.
	 * @return a valid index into the constant_pool table
	 */
	public int getInnerClassInfoIndex() {
		return innerClassInfoIndex & 0xffff;
	}

	/**
	 * If C is not a member of a class or an interface (that is, if C is a top-level
	 * class or interface (JLS ?7.6) or a local class or an anonymous
	 * class, the value of the outer_class_info_index item must
	 * be zero.
	 * <p>
	 * Otherwise, the value of the outer_class_info_index item must be a
	 * valid index into the constant_pool table, and the entry at that index must
	 * be a CONSTANT_Class_info structure representing the class or
	 * interface of which C is a member.
	 * @return a valid index into the constant_pool table, or zero
	 */
	public int getOuterClassInfoIndex() {
		return outerClassInfoIndex & 0xffff;
	}

	/**
	 * If C is anonymous (JLS ?15.9.5), the value of the inner_name_index item must be zero.
	 * <p>
	 * Otherwise, the value of the inner_name_index item must be a valid index
	 * into the constant_pool table, and the entry at that index must be a
	 * CONSTANT_Utf8_info (?4.4.7) structure that represents the original simple
	 * name of C, as given in the source code from which this class file was
	 * compiled.
	 * @return a valid index into the constant_pool table, or zero
	 */
	public int getInnerNameIndex() {
		return innerNameIndex & 0xffff;
	}

	/**
	 * The value of the inner_class_access_flags item is a mask of flags used
	 * to denote access permissions to and properties of class or interface C as
	 * declared in the source code from which this class file was compiled. It is
	 * used by compilers to recover the original information when source code is
	 * not available.
	 * The flags are shown in Table 4.23.
	 * @return a mask of flags used to denote access permissions to and properties of class or interface
	 */
	public short getInnerClassAccessFlags() {
		return innerClassAccessFlags;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = new StructureDataType("inner_class", 0);
		structure.add(WORD, "inner_class_info_index", null);
		structure.add(WORD, "outer_class_info_index", null);
		structure.add(WORD, "inner_name_index", null);
		structure.add(WORD, "inner_class_access_flags", null);
		return structure;
	}

}
