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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * This class in an artificial attribute (i.e., not defined in the JVM specification)
 * whose purpose is to consume attributes that are not (yet) supported by Ghidra
 * so that class file parsing can proceed.
 */
public class UnsupportedAttributeInfo extends AbstractAttributeInfo {

	/**
	 * Creates a {@code UnsupportedAttributeInfo} object from the current index of
	 * {@code reader} and advances the index.
	 * @param reader source of bytes
	 * @throws IOException thrown if problem reading bytes
	 */
	protected UnsupportedAttributeInfo(BinaryReader reader) throws IOException {
		super(reader);
		reader.setPointerIndex(reader.getPointerIndex() + getAttributeLength());
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("Unsupported_attribute");
		structure.add(new ArrayDataType(BYTE, getAttributeLength(), BYTE.getLength()));
		return structure;
	}

}
