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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * This class represents various flavors of High Level Shader Language symbol.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDataHighLevelShaderLanguageMsSymbol extends AbstractMsSymbol {

	protected AbstractDataHighLevelShaderLanguageSymbolInternals internals;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractDataHighLevelShaderLanguageMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		internals.parse(reader);
	}

	/**
	 * Returns the data offset.
	 * @return Data offset.
	 */
	public long getDataOffset() {
		return internals.getDataOffset();
	}

	/**
	 * Returns the register type.
	 * @return Register type.
	 */
	public String getRegisterType() {
		return internals.getRegisterType();
	}

	/**
	 * Returns the type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return internals.getTypeIndex();
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return internals.getName();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		internals.emit(builder);
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #internals}.
	 */
	protected abstract void create();

}
