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
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Internals of the High Level Shader Language symbol.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDataHighLevelShaderLanguageSymbolInternals
		extends AbstractSymbolInternals {

	//==============================================================================================
	/**
	 * Implementing class is required to parse these four fields in the
	 * {@link #parse(PdbByteReader)} method.
	 */
	protected int typeIndex;
	protected long dataOffset;
	protected HLSLRegisterType registerType;
	protected AbstractString name;

	//==============================================================================================
	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractDataHighLevelShaderLanguageSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	public long getDataOffset() {
		return dataOffset;
	}

	public HLSLRegisterType getRegisterType() {
		return registerType;
	}

	public int getTypeIndex() {
		return typeIndex;
	}

	public String getName() {
		return name.get();
	}

	@Override
	protected void create() {
		name = new StringUtf8Nt(pdb);
	}

}
