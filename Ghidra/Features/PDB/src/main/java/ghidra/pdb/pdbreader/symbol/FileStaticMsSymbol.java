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
 * This class represents the File Static symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class FileStaticMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1153;

	private int typeIndex;
	private int moduleFilenameStringTableIndex;
	private LocalVariableFlags localVariableFlags;
	private AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public FileStaticMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		name = new StringUtf8Nt(pdb);
		typeIndex = reader.parseInt();
		moduleFilenameStringTableIndex = reader.parseInt();
		localVariableFlags = new LocalVariableFlags(reader);
		name.parse(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return typeIndex;
	}

	/**
	 * Returns the module filename string table index.
	 * @return Module filename string table index.
	 */
	public int getModuleFilenameStringTableIndex() {
		return moduleFilenameStringTableIndex;
	}

	/**
	 * Returns the module filename.
	 * @return Module filename.
	 */
	public String getModuleFilename() {
		return pdb.getNameStringFromOffset(moduleFilenameStringTableIndex);
	}

	/**
	 * Returns the {@link LocalVariableFlags}.
	 * @return Local variable flags.
	 */
	public LocalVariableFlags getLocalVariableFlags() {
		return localVariableFlags;
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name.get();
	}

	@Override
	public void emit(StringBuilder builder) {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(String.format("%08X ", typeIndex));
		localVariableFlags.emit(myBuilder);
		builder.append(
			String.format("%s: %s, %s", getSymbolTypeName(), myBuilder.toString(), name.get()));
		builder.append("\n   Mod: ");
		// TODO....not sure this is correct:
		builder.append(pdb.getNameStringFromOffset(moduleFilenameStringTableIndex));
	}

	@Override
	protected String getSymbolTypeName() {
		return "FILESTATIC";
	}

}
