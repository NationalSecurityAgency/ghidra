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
import ghidra.pdb.pdbreader.StringUtf8Nt;

/**
 * This class represents the <B>MsSymbol</B> flavor of Managed Local- Or Parameter Stored
 *  in Many Register 2 symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ManagedLocalOrParameterStoredInManyRegister2MsSymbol
		extends AbstractManagedLocalOrParameterStoredInManyRegisterMsSymbol {

	public static final int PDB_ID = 0x1123;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public ManagedLocalOrParameterStoredInManyRegister2MsSymbol(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException {
		super(pdb, reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected void create() {
		name = new StringUtf8Nt();
	}

	@Override
	protected int parseVal(PdbByteReader reader) throws PdbException {
		return reader.parseUnsignedShortVal();
	}

	@Override
	protected String getSymbolTypeName() {
		return "MANMANYREG2";
	}

}
