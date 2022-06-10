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
 * This attribute records info about the (formal) parameters of a method,
 * such as parameter names.
 */
public class MethodParametersAttribute extends AbstractAttributeInfo {

	private byte parameters_count;
	private MethodParameters[] parameters;

	/**
	 * Creates a {@code MethodParametersAttribute} object from the current index of
	 * {@code reader} and advances index.
	 * @param reader source of bytes
	 * @throws IOException if problem reading bytes
	 */
	protected MethodParametersAttribute(BinaryReader reader) throws IOException {
		super(reader);
		parameters_count = reader.readNextByte();
		int size = Byte.toUnsignedInt(parameters_count);
		parameters = new MethodParameters[size];
		for (int i = 0; i < size; ++i) {
			parameters[i] = new MethodParameters(reader);
		}
	}

	/**
	 * Returns information about the parameters of the method
	 * @return parameter info
	 */
	public MethodParameters[] getMethodParameters() {
		return parameters;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("MethodParameters_attribute");
		structure.add(BYTE, "num_parameters", null);
		for (int i = 0; i < parameters.length; ++i) {
			structure.add(parameters[i].toDataType(), "parameter" + i, null);
		}
		return structure;
	}

}
