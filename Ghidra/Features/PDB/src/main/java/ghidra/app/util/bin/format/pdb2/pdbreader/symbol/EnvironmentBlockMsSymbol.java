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
 * This class represents the Environment Block symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class EnvironmentBlockMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x113d;

	private int flags;
	// TODO: MSFT API struct shows rev; usage shows fEC somewhere (not in struct)
	private boolean rev;
	/**
	 * These appear to be pairs of strings that we then output as
	 * <P>
	 * string1 = string2
	 * <P>
	 * string3 = string4...
	 */
	private List<String> stringList = new ArrayList<>();

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public EnvironmentBlockMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		flags = reader.parseUnsignedByteVal();
		while (reader.hasMore()) {
			String string = reader.parseString(pdb, StringParseType.StringUtf8Nt);
			if (string.isEmpty()) {
				break;
			}
			stringList.add(string);
		}
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	public int getFlags() {
		return flags;
	}

	public boolean isRev() {
		return rev;
	}

	/**
	 * Returns {@link List}&lt;{@link String}&gt
	 * @return {@String} list.
	 */
	public List<String> getStringList() {
		return stringList;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getSymbolTypeName());
		builder.append(":\n");
		builder.append(String.format("Compiled for edit and continue: %s\n", rev ? "yes" : "no"));
		if ((stringList.size() & 0x0001) == 0x0001) {
			return; // Some sort of problem that we are not dealing with.
		}
		builder.append("Command block: \n");
		for (int i = 0; i < stringList.size(); i += 2) {
			builder.append(
				String.format("   %s = '%s'\n", stringList.get(i), stringList.get(i + 1)));
		}
	}

	@Override
	protected String getSymbolTypeName() {
		return "ENVBLOCK";
	}

}
