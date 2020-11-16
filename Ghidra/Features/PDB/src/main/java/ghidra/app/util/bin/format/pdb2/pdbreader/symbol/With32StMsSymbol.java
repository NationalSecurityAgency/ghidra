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

/**
 * This class represents the <B>32StMsSymbol</B> flavor of With symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class With32StMsSymbol extends AbstractWithMsSymbol {

	public static final int PDB_ID = 0x0208;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public With32StMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader, 32, StringParseType.StringUtf8St);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "WITH32_ST";
	}

}
