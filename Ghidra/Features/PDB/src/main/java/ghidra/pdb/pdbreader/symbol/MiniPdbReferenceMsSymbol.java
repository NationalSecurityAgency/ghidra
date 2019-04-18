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
 * This class represents the Mini PDB Reference symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class MiniPdbReferenceMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x1160;

	private long coffSection;
	private int typeIndex;
	private int moduleIndex;
	private boolean isLocal; // versus global
	private boolean isData; // versus function
	private boolean isUserDefinedType;
	private boolean isLabel;
	private boolean isConst;
	private AbstractString name;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public MiniPdbReferenceMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		name = new StringUtf8Nt();
		long val = reader.parseUnsignedIntVal();
		moduleIndex = reader.parseUnsignedShortVal();
		int flags = reader.parseUnsignedShortVal();
		processFlags(flags);
		if (isUserDefinedType) {
			// Convert from known positive integer stored in a long to an integer.
			typeIndex = (int) val;
			pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex));
			pdb.popDependencyStack();
		}
		else {
			coffSection = val;
		}
		name.parse(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: ", getSymbolTypeName()));
		if (isUserDefinedType) {
			builder.append(String.format("(UDT) moduleIndex = %04X, TypeInformation = %s, %s\n",
				moduleIndex, pdb.getTypeRecord(typeIndex), name.get()));
		}
		else {
			builder.append(String.format("(%s) moduleIndex = %04X, coffSection = %X, %s\n",
				getLabel(), moduleIndex, coffSection, name.get()));
		}
	}

	@Override
	protected String getSymbolTypeName() {
		return "REF_MINIPDB";
	}

	private void processFlags(int flags) {
		isLocal = ((flags & 0x01) == 0x01);
		flags >>= 1;
		isData = ((flags & 0x01) == 0x01);
		flags >>= 1;
		isUserDefinedType = ((flags & 0x01) == 0x01);
		flags >>= 1;
		isLabel = ((flags & 0x01) == 0x01);
		flags >>= 1;
		isConst = ((flags & 0x01) == 0x01);
	}

	private String getLabel() {
		StringBuilder myBuilder = new StringBuilder();
		myBuilder.append(isLocal ? "local" : "global");
		if (isData) {
			myBuilder.append(" data");
		}
		else if (isLabel) {
			myBuilder.append(" label");
		}
		else if (isConst) {
			myBuilder.append(" const");
		}
		else {
			myBuilder.append(" func");
		}
		return myBuilder.toString();
	}

}
