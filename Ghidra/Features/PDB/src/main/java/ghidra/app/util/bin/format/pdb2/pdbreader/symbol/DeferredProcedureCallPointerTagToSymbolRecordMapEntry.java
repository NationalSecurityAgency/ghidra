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
 * This class represents and Entry for the Deferred Procedure Call Pointer Tag To Symbol Record Map
 *  symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class DeferredProcedureCallPointerTagToSymbolRecordMapEntry extends AbstractParsableItem {

	private long tagValue; //MSFT API says "unsigned int"
	private long symbolRecordOffset;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public DeferredProcedureCallPointerTagToSymbolRecordMapEntry(PdbByteReader reader)
			throws PdbException {
		tagValue = reader.parseUnsignedIntVal();
		symbolRecordOffset = reader.parseUnsignedIntVal();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("(%d, %X)", tagValue, symbolRecordOffset));
	}

}
