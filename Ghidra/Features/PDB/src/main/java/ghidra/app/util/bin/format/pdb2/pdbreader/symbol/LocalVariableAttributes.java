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
 * Local Variable Attributes for certain PDB symbols.
 */
public class LocalVariableAttributes extends AbstractParsableItem {

	private long offset;
	private int segment;
	private LocalVariableFlags flags;

	/**
	 * Constructor for this symbol component.
	 * @param pdb {@link AbstractPdb} to which these symbol attributes belongs.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public LocalVariableAttributes(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		offset = reader.parseUnsignedIntVal();
		segment = pdb.parseSegment(reader);
		flags = new LocalVariableFlags(reader);
	}

	@Override
	public void emit(StringBuilder builder) {
		flags.emit(builder);
		builder.insert(0, String.format("[%04X:%08X]: ", segment, offset));
	}

}
