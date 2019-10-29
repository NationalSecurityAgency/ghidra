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
 * The Signature attribute is an optional fixed-length attribute in the attributes
 * table of a ClassFile, field_info or method_info structure.
 * The Signature attribute records generic signature information for any class,
 * interface, constructor or member whose generic signature in the Java programming
 * language would include references to type variables or parameterized types.
 * <p>
 * The Signature attribute has the following format:
 * <pre>
 * 	Signature_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 signature_index;
 * 	}
 * </pre>
 */
public class SignatureAttribute extends AbstractAttributeInfo {

	private short signatureIndex;

	public SignatureAttribute(BinaryReader reader) throws IOException {
		super(reader);

		signatureIndex = reader.readNextShort();
	}

	/**
	 * The value of the signature_index item must be a valid index into the
	 * constant_pool table. The constant pool entry at that index must be a
	 * CONSTANT_Utf8_info structure representing either a class signature,
	 * if this signature attribute is an attribute of a ClassFile structure, a method type
	 * signature, if this signature is an attribute of a method_info structure, or a field
	 * type signature otherwise.
	 * @return a valid index into the constant_pool table
	 */
	public int getSignatureIndex() {
		return signatureIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("Signature_attribute");
		structure.add(WORD, "signature_index", null);
		return structure;
	}

}
