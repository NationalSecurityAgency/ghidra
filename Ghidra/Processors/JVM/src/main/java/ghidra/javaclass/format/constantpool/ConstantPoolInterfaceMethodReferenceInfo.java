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
package ghidra.javaclass.format.constantpool;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ConstantPoolInterfaceMethodReferenceInfo extends AbstractConstantPoolReferenceInfo {

	public ConstantPoolInterfaceMethodReferenceInfo(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = (StructureDataType) super.toDataType();
		try {
			structure.setName("CONSTANT_InterfaceMethodref_info");
		}
		catch (InvalidNameException e) {
			throw new IOException(e);
		}
		return structure;
	}

}
