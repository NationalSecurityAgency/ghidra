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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * Each frame (2.6) contains an array of variables known as its local variables. The
 * length of the local variable array of a frame is determined at compile-time and
 * supplied in the binary representation of a class or interface along with the code for
 * the method associated with the frame (4.7.3).
 * <p>
 * A single local variable can hold a value of type:
 * <ol>
 * 		<li>boolean</li>
 * 		<li>byte</li>
 * 		<li>char</li> 
 * 		<li>short</li>
 * 		<li>int</li>
 * 		<li>float</li>
 * 		<li>reference</li>
 * 		<li>returnAddress</li> 
 * </ol>
 * A pair of local variables can hold a value of type:
 * <ol>
 * 		<li>long</li>
 * 		<li>double</li>
 * </ol>
 * <p>
 * Local variables are addressed by indexing. The index of the first local variable is
 * zero. An integer is considered to be an index into the local variable array if and only
 * if that integer is between zero and one less than the size of the local variable array.
 * <p>
 * A value of type long or type double occupies two consecutive local variables.
 * Such a value may only be addressed using the lesser index. For example, a value of
 * type double stored in the local variable array at index n actually occupies the local
 * variables with indices n and n+1; however, the local variable at index n+1 cannot
 * be loaded from. It can be stored into. However, doing so invalidates the contents
 * of local variable n.
 * <p>
 * The Java virtual machine does not require n to be even. In intuitive terms, values
 * of types long and double need not be 64-bit aligned in the local variables array.
 * Implementors are free to decide the appropriate way to represent such values using
 * the two local variables reserved for the value.
 * <p>
 * The Java virtual machine uses local variables to pass parameters on method
 * invocation. On class method invocation, any parameters are passed in consecutive
 * local variables starting from local variable 0. On instance method invocation,
 * local variable 0 is always used to pass a reference to the object on which the
 * instance method is being invoked (this in the Java programming language). Any
 * parameters are subsequently passed in consecutive local variables starting from
 * local variable 1.
 * <p>
 * Each classes array entry contains the following four items:
 * <pre>
 * 	local_variable {
 * 		u2 start_pc;
 * 		u2 length;
 * 		u2 name_index;
 * 		u2 descriptor_index;
 * 		u2 index;
 * 	}
 * </pre>
 */
public class LocalVariableJava implements StructConverter {

	private short startPC;
	private short length;
	private short nameIndex;
	private short descriptorIndex;
	private short index;

	public LocalVariableJava(BinaryReader reader) throws IOException {
		startPC = reader.readNextShort();
		length = reader.readNextShort();
		nameIndex = reader.readNextShort();
		descriptorIndex = reader.readNextShort();
		index = reader.readNextShort();
	}

	/**
	 * The given local variable must have a value at indices into the code array in
	 * the interval [start_pc, start_pc + length), that is, between start_pc
	 * inclusive and start_pc + length exclusive.
	 * <p>
	 * The value of start_pc must be a valid index into the code array of this
	 * Code attribute and must be the index of the opcode of an instruction.
	 * <p>
	 * The value of start_pc + length must either be a valid index into the code
	 * array of this Code attribute and be the index of the opcode of an instruction,
	 * or it must be the first index beyond the end of that code array.
	 * @return the start PC
	 */
	public int getStartPC() {
		return startPC & 0xffff;
	}

	/**
	 * Returns the length of this local variable in bytes.
	 * @return the length of this local variable in bytes
	 */
	public int getLength() {
		return length & 0xffff;
	}

	/**
	 * The value of the name_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must contain
	 * a CONSTANT_Utf8_info structure representing a valid unqualified
	 * name denoting a local variable.
	 * @return a valid index into the constant_pool table
	 */
	public int getNameIndex() {
		return nameIndex & 0xffff;
	}

	/**
	 * The value of the descriptor_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must contain
	 * a CONSTANT_Utf8_info structure representing a field descriptor
	 * encoding the type of a local variable in the source program.
	 * @return a valid index into the constant_pool table
	 */
	public int getDescriptorIndex() {
		return descriptorIndex & 0xffff;
	}

	/**
	 * The given local variable must be at index in the local variable array of the
	 * current frame.
	 * <p>
	 * If the local variable at index is of type double or long, it occupies both
	 * index and index + 1.
	 * @return index in the local variable array
	 */
	public int getIndex() {
		return index & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("local_variable", 0);
		structure.add(WORD, "start_pc", null);
		structure.add(WORD, "length", null);
		structure.add(WORD, "name_index", null);
		structure.add(WORD, "descriptor_index", null);
		structure.add(WORD, "index", null);
		return structure;
	}

}
