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
package ghidra.javaclass.format.constantpool;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The CONSTANT_MethodHandle_info structure is used to represent a method handle:
 * <pre>
 * 		CONSTANT_MethodHandle_info {
 * 			u1 tag;
 * 			u1 reference_kind;
 * 			u2 reference_index;
 * 		}
 * </pre>
 */
public class ConstantPoolMethodHandleInfo extends AbstractConstantPoolInfoJava {

	private byte referenceKind;
	private short referenceIndex;

	public ConstantPoolMethodHandleInfo(BinaryReader reader) throws IOException {
		super(reader);
		referenceKind = reader.readNextByte();
		referenceIndex = reader.readNextShort();
	}

	/**
	 * The value of the reference_kind item must be in the range 1 to 9. The
	 * value denotes the kind of this method handle, which characterizes its bytecode
	 * behavior.
	 * @return this method handle bytecode behavior
	 */
	public byte getReferenceKind() {
		return referenceKind;
	}

	/** 
	 * The value of the reference_index item must be a valid index into the
	 * constant_pool table.
	 * <p>
	 * If the value of the reference_kind item is 
	 * 		1 (REF_getField), 
	 * 		2 (REF_getStatic), 
	 * 		3 (REF_putField), or 
	 * 		4 (REF_putStatic), 
	 * then the constant_pool entry at that index must be a CONSTANT_Fieldref_info
	 * structure representing a field for which a method handle is to be
	 * created.
	 * <p>
	 * If the value of the reference_kind item is 
	 * 		5 (REF_invokeVirtual), 
	 * 		6 (REF_invokeStatic), 
	 * 		7 (REF_invokeSpecial), or 
	 * 		8 (REF_newInvokeSpecial), 
	 * then the constant_pool entry at that index must be
	 * a CONSTANT_Methodref_info structure representing a class's method
	 * or constructor for which a method handle is to be created.
	 * <p>
	 * If the value of the reference_kind item is 
	 * 		9 (REF_invokeInterface),
	 * then the constant_pool entry at that index must be a
	 * CONSTANT_InterfaceMethodref_info structure representing an
	 * interface's method for which a method handle is to be created.
	 * <p>
	 * If the value of the reference_kind item is 
	 * 		5 (REF_invokeVirtual),
	 * 		6 (REF_invokeStatic), 
	 * 		7 (REF_invokeSpecial), or 
	 * 		9 (REF_invokeInterface),
	 * the name of the method represented by a CONSTANT_Methodref_info structure
	 * must not be <init> or <clinit>.
	 * <p>
	 * If the value is 
	 * 		8 (REF_newInvokeSpecial), 
	 * the name of the method represented by a 
	 * CONSTANT_Methodref_info structure must be <init>.
	 * 
	 * @return a valid index into the constant_pool table
	 */
	public int getReferenceIndex() {
		return referenceIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_MethodHandle_info";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(BYTE, "reference_kind", null);
		structure.add(WORD, "reference_index", null);
		return structure;
	}

}
