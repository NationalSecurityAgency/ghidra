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
 * Range Attribute component for certain PDB symbols.
 */
public class RangeAttribute extends AbstractParsableItem {

	private int attributes;
	private boolean mayHaveNoUserNameOnAControlFlowPath;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public RangeAttribute(PdbByteReader reader) throws PdbException {
		attributes = reader.parseUnsignedShortVal();
		processAttributes(attributes);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append("Attributes: ");
		builder.append(mayHaveNoUserNameOnAControlFlowPath ? "MayAvailable" : "");
	}

	private void processAttributes(int val) {
		mayHaveNoUserNameOnAControlFlowPath = ((val & 0x0001) == 0x0001);
	}

}
