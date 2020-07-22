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
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DataHighLevelShaderLanguageSymbolInternals.DataHighLevelShaderLanguageSymbolInternals32;

/**
 * This class represents the <B>MsSymbol</B> flavor of Global High Level Shader Language symbol.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class GlobalDataHLSLMsSymbol extends AbstractGlobalDataHLSLMsSymbol {

	public static final int PDB_ID = 0x1151;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public GlobalDataHLSLMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader, DataHighLevelShaderLanguageSymbolInternals.parse(pdb, reader));
	}

	/**
	 * Return the data slot.
	 * @return the data slot.
	 */
	public long getDataSlot() {
		return ((DataHighLevelShaderLanguageSymbolInternals32) internals).getDataSlot();
	}

	/**
	 * Return the texture slot start.
	 * @return the texture slot start.
	 */
	public long getTextureSlotStart() {
		return ((DataHighLevelShaderLanguageSymbolInternals32) internals).getTextureSlotStart();
	}

	/**
	 * Return the sampler slot start.
	 * @return the sampler slot start.
	 */
	public long getSamplerSlotStart() {
		return ((DataHighLevelShaderLanguageSymbolInternals32) internals).getSamplerSlotStart();
	}

	/**
	 * Return the UAV slot start.
	 * @return the UAV slot start.
	 */
	public long getUavSlotStart() {
		return ((DataHighLevelShaderLanguageSymbolInternals32) internals).getUavSlotStart();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "GDATA_HLSL";
	}

}
