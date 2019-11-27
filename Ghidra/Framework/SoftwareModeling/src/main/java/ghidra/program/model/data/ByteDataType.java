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
 * Provides a definition of a Byte within a program.
 */
public class ByteDataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined ByteDataType instance.*/
	public final static ByteDataType dataType = new ByteDataType();

	public ByteDataType() {
		this(null);
	}

	public ByteDataType(DataTypeManager dtm) {
		super("byte", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned Byte (db)";
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public String getAssemblyMnemonic() {
		return "db";
	}

	@Override
	public String getDecompilerDisplayName(DecompilerLanguage language) {
		if (language == DecompilerLanguage.JAVA_LANGUAGE)
			return "ubyte";
		return name;
	}

	@Override
	public SignedByteDataType getOppositeSignednessDataType() {
		return SignedByteDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public ByteDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new ByteDataType(dtm);
	}

}
