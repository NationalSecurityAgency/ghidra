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
 * This class represents the Local Deferred Procedure Call Group Shared symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class LocalDeferredProcedureCallGroupSharedMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1154;

	private RecordNumber typeRecordNumber;
	private LocalVariableFlags flags;
	private int dataSlot;
	private int dataOffset;
	private String name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public LocalDeferredProcedureCallGroupSharedMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		typeRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		flags = new LocalVariableFlags(reader);
		dataSlot = reader.parseUnsignedShortVal();
		dataOffset = reader.parseUnsignedShortVal();
		name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(typeRecordNumber.getNumber());
		flags.emit(myBuilder);
		builder.append(String.format("%s: %s base data: slot = %d offset = %d, %s",
			getSymbolTypeName(), myBuilder.toString(), dataSlot, dataOffset, name));
	}

	@Override
	protected String getSymbolTypeName() {
		return "LOCAL_DPC_GROUPSHARED";
	}

}
