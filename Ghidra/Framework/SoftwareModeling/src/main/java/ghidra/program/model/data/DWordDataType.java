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
 * Provides a definition of a Double Word within a program.
 */
public class DWordDataType extends AbstractIntegerDataType {

	private static final long serialVersionUID = 1L;

	/** A statically defined DWordDataType instance.*/
	public final static DWordDataType dataType = new DWordDataType();

	public DWordDataType() {
		this(null);
	}

	public DWordDataType(DataTypeManager dtm) {
		super("dword", false, dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned Double-Word (ddw, 4-bytes)";
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getAssemblyMnemonic() {
		return "ddw";
	}

	@Override
	public SignedDWordDataType getOppositeSignednessDataType() {
		return SignedDWordDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public DWordDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new DWordDataType(dtm);
	}

}
