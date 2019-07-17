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
 * The BootstrapMethods attribute is a variable-length attribute in the attributes
 * table of a ClassFile structure.
 *  
 * The BootstrapMethods attribute records bootstrap method specifiers 
 * referenced by invokedynamic instructions.
 * 
 * There must be exactly one BootstrapMethods attribute in the attributes table of
 * a given ClassFile structure if the constant_pool table of the ClassFile structure
 * has at least one CONSTANT_InvokeDynamic_info entry. 
 * 
 * There can be no more than one BootstrapMethods attribute in the attributes table of a given
 * ClassFile structure.
 * 
 * The BootstrapMethods attribute has the following format:
 * <pre>
 * 		BootstrapMethods_attribute {
 * 			u2 attribute_name_index;
 * 			u4 attribute_length;
 * 			u2 num_bootstrap_methods;
 * 			{
 * 				u2 bootstrap_method_ref;
 * 				u2 num_bootstrap_arguments;
 * 				u2 bootstrap_arguments[num_bootstrap_arguments];
 * 			} bootstrap_methods[num_bootstrap_methods];
 * 		}
 * </pre>
 */
public class BootstrapMethodsAttribute extends AbstractAttributeInfo {

	private short numberOfBootstrapMethods;
	private BootstrapMethods[] bootstrapMethods;

	public BootstrapMethodsAttribute(BinaryReader reader) throws IOException {
		super(reader);

		numberOfBootstrapMethods = reader.readNextShort();

		bootstrapMethods = new BootstrapMethods[getNumberOfBootstrapMethods()];
		for (int i = 0; i < getNumberOfBootstrapMethods(); ++i) {
			bootstrapMethods[i] = new BootstrapMethods(reader);
		}
	}

	public int getNumberOfBootstrapMethods() {
		return numberOfBootstrapMethods & 0xffff;
	}

	public BootstrapMethods[] getBootstrapMethods() {
		return bootstrapMethods;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("BootstrapMethods_attribute");
		structure.add(WORD, "num_bootstrap_methods", null);
		for (int i = 0; i < bootstrapMethods.length; ++i) {
			structure.add(bootstrapMethods[i].toDataType(), "bootstrap_methods" + i, null);
		}
		return structure;
	}

}
