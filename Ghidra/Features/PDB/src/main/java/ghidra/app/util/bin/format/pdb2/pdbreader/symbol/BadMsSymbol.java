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

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;

/**
 * Important: This is not a real symbol.  This "Bad" symbol takes the place of a symbol that has
 *  encountered a parsing issue vis-a-vis a PdbException.
 */
public class BadMsSymbol extends AbstractMsSymbol {

	/** This should not be a the PDB_ID value of a real AbstractMsSymbol. */
	public static final int PDB_ID = 0xff01;

	// Symbol ID that had an issue;
	int symbolId;

	/**
	 * Constructor for this "Bad" symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param symbolId The type ID for which an error occurred.
	 */
	public BadMsSymbol(AbstractPdb pdb, int symbolId) {
		super(pdb, null);
		this.symbolId = symbolId;
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		if (builder.length() != 0) {
			builder.insert(0, " ");
		}
		builder.insert(0, String.format("BAD_SYMBOL: ID=0X%04X", symbolId));
	}

	@Override
	protected String getSymbolTypeName() {
		return "BAD";
	}

}
