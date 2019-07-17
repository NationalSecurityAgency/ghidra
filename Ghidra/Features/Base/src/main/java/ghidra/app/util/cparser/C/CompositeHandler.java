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
package ghidra.app.util.cparser.C;

import ghidra.program.model.data.*;

/**
 * Used by the CParser to handle fields added to structures(composites).
 * Currently only bitfields are handled specially.
 * 
 * NOTE: when bitfield handling is added directly to structures, this class may
 * no longer be necessary.
 * 
 */

public class CompositeHandler {

	private Composite parent; // parent container for bitfields

	public CompositeHandler(Composite parent) {
		super();
		this.parent = parent;
	}

	public Composite getComposite() {
		return parent;
	}

	public void add(Declaration dec) throws IllegalArgumentException {
		if (dec == null || dec.getDataType() == null) {
			return;
		}
		if (parent instanceof Structure) {
			// ensure that only the last component establishes a structure's flex array
			((Structure) parent).clearFlexibleArrayComponent();
		}
		// not a bitfield, just add the data type to composite
		if (!dec.isBitField()) {
			if (dec.isFlexArray() && parent instanceof Structure) {
				((Structure) parent).setFlexibleArrayComponent(dec.getDataType(), dec.getName(),
					dec.getComment());
				return;
			}
			parent.add(dec.getDataType(), dec.getName(), dec.getComment());
			return;
		}

		// add bit-field component
		DataType dataType = dec.getDataType();
		try {
			parent.addBitField(dataType, dec.getBitFieldSize(), dec.getName(), dec.getComment());
		}
		catch (InvalidDataTypeException e) {
			// TODO Auto-generated catch block
			throw new IllegalArgumentException(
				"Invalid bitfield " + dec.getName() + " : " + dec.getBitFieldSize());
		}
	}

}
