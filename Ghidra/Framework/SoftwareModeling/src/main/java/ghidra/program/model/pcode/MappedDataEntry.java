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
package ghidra.program.model.pcode;

import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.VariableStorage;

/**
 * A normal address based HighSymbol mapping with an associated Data object
 */
public class MappedDataEntry extends MappedEntry {
	private Data data;			// Backing data object

	/**
	 * Constructor for use with restoreXML
	 * @param sym is the owning HighSymbol
	 */
	public MappedDataEntry(HighSymbol sym) {
		super(sym);
	}

	/**
	 * Construct given a symbol, storage, and a backing Data object
	 * @param sym the given symbol
	 * @param store the given storage
	 * @param d the backing Data object
	 */
	public MappedDataEntry(HighSymbol sym, VariableStorage store, Data d) {
		super(sym, store, null);
		data = d;
	}

	/**
	 * @return the backing Data object
	 */
	public Data getData() {
		return data;
	}

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		super.decode(decoder);
		data = symbol.getProgram().getListing().getDataAt(storage.getMinAddress());
	}

	@Override
	public int getMutability() {
		if (data.isVolatile()) {
			return MutabilitySettingsDefinition.VOLATILE;
		}
		if (data.isConstant()) {
			return MutabilitySettingsDefinition.CONSTANT;
		}
		if (data.isWritable()) {
			return MutabilitySettingsDefinition.NORMAL;
		}
		return super.getMutability();
	}
}
