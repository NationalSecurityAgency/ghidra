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
 * Pointer-sized signed integer 
 */
public class PointerSizedIntegerDataType extends AbstractSignedIntegerDataType {

	public final static PointerSizedIntegerDataType dataType = new PointerSizedIntegerDataType();

	public PointerSizedIntegerDataType() {
		this(null);
	}

	public PointerSizedIntegerDataType(DataTypeManager dtm) {
		super("intptr_t", dtm);
	}

	@Override
	public int getLength() {
		return getDataOrganization().getPointerSize();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public String getDescription() {
		return "Signed Pointer-Sized Integer (compiler-specific size)";
	}

	@Override
	public String getCDeclaration() {
		return null;
	}

	@Override
	public UnsignedPointerSizedIntegerDataType getOppositeSignednessDataType() {
		return UnsignedPointerSizedIntegerDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public PointerSizedIntegerDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PointerSizedIntegerDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
