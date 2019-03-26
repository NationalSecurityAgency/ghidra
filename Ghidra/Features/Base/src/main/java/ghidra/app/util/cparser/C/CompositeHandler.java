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
	private DataType lastBitFieldType = null; // type that has a bitfield
	private int bitLength = 0; // how many bits have been used
	private int anonCnt = 0; // count of anonymous unions created
	private Composite parent; // parent container for bitfields
	private Composite bitFieldUnion; // artificial union to contain subfields

	public CompositeHandler(Composite parent) {
		super();
		this.parent = parent;
	}

	public Composite getComposite() {
		return parent;
	}

	public void add(Declaration dec) {
		if (dec == null || dec.getDataType() == null) {
			return;
		}
		if (parent instanceof Structure) {
			// ensure that only the last component establishes a structure's flex array
			((Structure) parent).clearFlexibleArrayComponent();
		}
		// not a bitfield, just add the data type to composite
		if (!dec.isBitField()) {
			initialize();
			if (dec.isFlexArray() && parent instanceof Structure) {
				((Structure) parent).setFlexibleArrayComponent(dec.getDataType(), dec.getName(),
					dec.getComment());
				return;
			}
			parent.add(dec.getDataType(), dec.getName(), dec.getComment());
			return;
		}

		DataType dataType = dec.getDataType();
		int bitSize = dec.getBitFieldSize();

		// if data type different, start new subfield
		handleFullBitfieldUnion(dataType, bitSize);

		// add the bitfield to the continer union
		String bitoff =
			(bitSize == 1 ? "" + bitLength : bitLength + "-" + (bitLength + bitSize - 1));
		bitFieldUnion.add(dataType, dec.getName(), ": bits " + bitoff);
		lastBitFieldType = dataType;
		bitLength += bitSize;
	}

	/**
	 * Creates a new bitfield union container if one not created yet or the current
	 * is full.
	 * 
	 * @param dataType - type that is about to be added to container
	 * @param bitSize
	 */
	private void handleFullBitfieldUnion(DataType dataType, int bitSize) {
		if (!bitfieldFull(dataType, bitSize)) {
			return;
		}
		// create an anonymous union to hold sub bitfields
		bitFieldUnion = new UnionDataType(parent.getCategoryPath(),
			"anon_" + parent.getName() + "_bitfield_" + ++anonCnt);
		bitFieldUnion = (Composite) parent.add(bitFieldUnion).getDataType();
		bitLength = 0;
	}

	/**
	 * Check if a new union needs to be created
	 * 
	 * @param dataType type that will be added to the union
	 * @param bitSize size of the bitfield to be added
	 * 
	 * @return true if a new bitfied union needs to be added
	 */
	private boolean bitfieldFull(DataType dataType, int bitSize) {
		if (parent instanceof Union) {
			bitFieldUnion = parent;
			return false;
		}

		// no union yet
		if (bitFieldUnion == null) {
			return true;
		}

		// datatype has changed
		if (!dataType.equals(lastBitFieldType)) {
			return true;
		}
		// union has overflowed
		return (bitLength + bitSize) > (dataType.getLength() * 8);
	}

	/**
	 * Clears any residual bitfield info so a new bitfield container will
	 * be created when necessary.
	 */
	private void initialize() {
		lastBitFieldType = null;
		bitLength = 0;
		bitFieldUnion = null;
	}
}
