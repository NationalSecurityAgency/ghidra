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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DataHighLevelShaderLanguageSymbolInternals.DataHighLevelShaderLanguageSymbolInternals32Extended;

/**
 * This class represents the <B>Extended 32MsSymbol</B> flavor of Global High Level Shader
 * Language symbol.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class GlobalDataHLSL32ExtMsSymbol extends AbstractGlobalDataHLSLMsSymbol {

	public static final int PDB_ID = 0x1164;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public GlobalDataHLSL32ExtMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader,
			DataHighLevelShaderLanguageSymbolInternals.parse32Ext(pdb, reader));
	}

	/**
	 * Return the register index.
	 * @return the register index.
	 */
	public long getRegisterIndex() {
		return ((DataHighLevelShaderLanguageSymbolInternals32Extended) internals).getRegisterIndex();
	}

	/**
	 * Return the bind space.
	 * @return the bind space.
	 */
	public long getBindSpace() {
		return ((DataHighLevelShaderLanguageSymbolInternals32Extended) internals).getBindSpace();
	}

	/**
	 * Return the bind slot.
	 * @return the bind slot.
	 */
	public long getBindSlot() {
		return ((DataHighLevelShaderLanguageSymbolInternals32Extended) internals).getBindSlot();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "GDATA_HLSL32_EX";
	}

}
