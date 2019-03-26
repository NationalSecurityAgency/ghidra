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

/**
 * Provides a basic implementation of a signed word datatype
 */
public class SignedWordDataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined SignedWordDataType instance.*/
	public final static SignedWordDataType dataType = new SignedWordDataType();

	public SignedWordDataType() {
		this(null);
	}

	public SignedWordDataType(DataTypeManager dtm) {
		super("sword", true, dtm);
	}

	@Override
	public String getDescription() {
		return "Signed Word (sdw, 2-bytes)";
	}

	@Override
	public int getLength() {
		return 2;
	}

	@Override
	public String getAssemblyMnemonic() {
		return "sdw";
	}

	@Override
	public WordDataType getOppositeSignednessDataType() {
		return WordDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public SignedWordDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new SignedWordDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
