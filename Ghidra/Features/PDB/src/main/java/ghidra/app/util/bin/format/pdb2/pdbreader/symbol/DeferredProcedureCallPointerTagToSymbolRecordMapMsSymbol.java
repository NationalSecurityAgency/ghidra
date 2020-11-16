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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the Deferred Procedure Call Pointer Tag To Symbol Record Map symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1158;

	private List<DeferredProcedureCallPointerTagToSymbolRecordMapEntry> mapList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		while (reader.hasMore()) {
			DeferredProcedureCallPointerTagToSymbolRecordMapEntry entry =
				new DeferredProcedureCallPointerTagToSymbolRecordMapEntry(reader);
			mapList.add(entry);
		}
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: %d entries", getSymbolTypeName(), mapList.size()));
		for (DeferredProcedureCallPointerTagToSymbolRecordMapEntry entry : mapList) {
			builder.append(String.format(", %s", entry.toString()));
		}
		builder.append("\n");
	}

	@Override
	protected String getSymbolTypeName() {
		return "DPC_SYM_TAG_MAP";
	}

}
