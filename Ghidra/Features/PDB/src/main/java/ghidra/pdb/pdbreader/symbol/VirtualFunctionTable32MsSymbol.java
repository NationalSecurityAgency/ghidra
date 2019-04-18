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
import ghidra.pdb.pdbreader.*;

/**
 * This class represents the <B>32MsSymbol</B> flavor of Virtual Function Table symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class VirtualFunctionTable32MsSymbol extends AbstractVirtualFunctionTableMsSymbol {

	public static final int PDB_ID = 0x100c;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public VirtualFunctionTable32MsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void create() {
		offset = new Offset32();
		rootTypeIndex = new TypeIndex32();
		pathTypeIndex = new TypeIndex32();
	}

	@Override
	protected void parse(PdbByteReader reader) throws PdbException {
		rootTypeIndex.parse(reader);
		pathTypeIndex.parse(reader);
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
	}

	@Override
	protected String getSymbolTypeName() {
		return "VFTABLE32";
	}

}
