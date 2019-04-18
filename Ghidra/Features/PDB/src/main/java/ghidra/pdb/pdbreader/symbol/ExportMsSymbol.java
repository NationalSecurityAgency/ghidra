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
 * This class represents the Export symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ExportMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1138;

	private int ordinal;
	private boolean isConstant;
	private boolean isData;
	private boolean isPrivate;
	private boolean noName;
	private boolean ordinalExplicitlyAssigned;
	private boolean isForwarder;
	private AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public ExportMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		name = new StringUtf8Nt();
		ordinal = reader.parseUnsignedShortVal();
		int flags = reader.parseUnsignedShortVal();
		processFlags(flags);
		name.parse(reader);
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: Ordinal = %d%s, ", getSymbolTypeName(), ordinal,
			ordinalExplicitlyAssigned ? "" : " (implicit)"));
		builder.append(isConstant ? "CONSTANT, " : "");
		builder.append(isData ? "DATA, " : "");
		builder.append(isPrivate ? "PRIVATE, " : "");
		builder.append(noName ? "NONAME, " : "");
		builder.append(isForwarder ? "FORWARDER, " : "");
		builder.append(name.get());
	}

	@Override
	protected String getSymbolTypeName() {
		return "EXPORT";
	}

	/**
	 * Internal method that breaks out the flag values from the aggregate integral type.
	 * @param flagsIn {@code int} containing unsigned short value.
	 */
	protected void processFlags(int flagsIn) {
		isConstant = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isData = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isPrivate = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		noName = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		ordinalExplicitlyAssigned = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isForwarder = ((flagsIn & 0x0001) == 0x0001);
	}

}
