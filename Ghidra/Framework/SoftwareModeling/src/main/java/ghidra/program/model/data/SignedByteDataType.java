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
package ghidra.program.model.data;

import ghidra.program.model.lang.DecompilerLanguage;

/**
 * Provides a definition of a Signed Byte within a program.
 */
public class SignedByteDataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined SignedByteDataType instance.*/
	public final static SignedByteDataType dataType = new SignedByteDataType();

	public SignedByteDataType() {
		this(null);
	}

	public SignedByteDataType(DataTypeManager dtm) {
		super("sbyte", true, dtm);
	}

	@Override
	public String getDescription() {
		return "Signed Byte (sdb)";
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public String getAssemblyMnemonic() {
		return "sdb";
	}

	@Override
	public String getDecompilerDisplayName(DecompilerLanguage language) {
		if (language == DecompilerLanguage.JAVA_LANGUAGE)
			return "byte";
		return name;
	}

	@Override
	public ByteDataType getOppositeSignednessDataType() {
		return ByteDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public SignedByteDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new SignedByteDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
