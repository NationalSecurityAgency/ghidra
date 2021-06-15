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
 * This class represents the <B>32MsSymbol</B> flavor of Change Model Execution symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ChangeExecutionModel32MsSymbol extends AbstractChangeExecutionModelMsSymbol {

	public static final int PDB_ID = 0x020a;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ChangeExecutionModel32MsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader, 32);
		parseSpecifics(reader);
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	protected String getSymbolTypeName() {
		return "CEXMODEL32";
	}

	protected void parseSpecifics(PdbByteReader reader) throws PdbException {
		switch (model) {
			case COBOL:
				// subtype (API: values are missing)
				subtype = reader.parseUnsignedShortVal();
				flag = reader.parseUnsignedShortVal();
				break;
			case PCODE:
				offsetToPcodeFunctionTable = reader.parseUnsignedIntVal();
				offsetToSegmentPcodeInformation = reader.parseUnsignedIntVal();
				break;
			case PCODE32MACINTOSH:
			case PCODE32MACINTOSH_NATIVE_ENTRY_POINT:
				offsetToFunctionTable = reader.parseUnsignedIntVal();
				segmentOfFunctionTable = reader.parseUnsignedShortVal();
				break;
			default:
				break;
		}
	}

}
