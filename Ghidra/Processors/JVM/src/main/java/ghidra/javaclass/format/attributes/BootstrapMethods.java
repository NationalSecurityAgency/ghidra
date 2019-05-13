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
 * 
 * NOTE: THE COMMENT TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 */
public class BootstrapMethods implements StructConverter {

	private short bootstrapMethodsReference;
	private short numberOfBootstrapArguments;
	private short[] bootstrapArguments;

	public BootstrapMethods(BinaryReader reader) throws IOException {
		bootstrapMethodsReference = reader.readNextShort();
		numberOfBootstrapArguments = reader.readNextShort();
		bootstrapArguments = reader.readNextShortArray(getNumberOfBootstrapArguments());
	}

	/**
	 * The value of the bootstrap_method_ref item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index must be
	 * a CONSTANT_MethodHandle_info structure.
	 * 
	 * Commentary: The reference_kind item of the CONSTANT_MethodHandle_info
	 * structure should have the value 6 (REF_invokeStatic) or 8 (REF_newInvokeSpecial) 
	 * or else invocation of the bootstrap method
	 * handle during call site specifier resolution for an invokedynamic instruction will
	 * complete abruptly.
	 * 
	 * @return a valid index into the constant_pool table
	 */
	public int getBootstrapMethodsReference() {
		return bootstrapMethodsReference & 0xffff;
	}

	/**
	 * The value of the num_bootstrap_arguments item gives the number of
	 * items in the bootstrap_arguments array.
	 * @return the number of items in the bootstrap_arguments array
	 */
	public int getNumberOfBootstrapArguments() {
		return numberOfBootstrapArguments & 0xffff;
	}

	/**
	 * Each entry in the bootstrap_arguments array must be a valid index into
	 * the constant_pool table. 
	 * The constant_pool entry at that index must be: 
	 * 		CONSTANT_String_info, 
	 * 		CONSTANT_Class_info,
	 * 		CONSTANT_Integer_info, 
	 * 		CONSTANT_Long_info,
	 * 		CONSTANT_Float_info, 
	 * 		CONSTANT_Double_info,
	 * 		CONSTANT_MethodHandle_info, or 
	 * 		CONSTANT_MethodType_info structure.
	 * @param i entry
	 * @return index
	 */
	public int getBootstrapArgumentsEntry(int i) {
		return bootstrapArguments[i] & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = new StructureDataType("bootstrap_methods", 0);
		structure.add(WORD, "bootstrap_method_ref", null);
		structure.add(WORD, "num_bootstrap_arguments", null);
		if (numberOfBootstrapArguments > 0) {
			DataType array = new ArrayDataType(WORD, numberOfBootstrapArguments, WORD.getLength());
			structure.add(array, "bootstrapArguments", null);
		}
		return structure;
	}
}
