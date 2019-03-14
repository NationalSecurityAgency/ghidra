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
package ghidra.util.state.analysis;

import ghidra.program.model.address.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.state.VarnodeOperation;

class TableEntryAddress extends Switch {

	private final Address tableBase;
	private final ComputedTableOffset tableOffset;

	TableEntryAddress(Address tableBase, ComputedTableOffset tableOffset) {
		this.tableBase = tableBase;
		this.tableOffset = tableOffset;
	}

	/**
	 * Returns base address of table
	 */
	Address getTableBaseAddress() {
		return tableBase;
	}

	/**
	 * Get the address of the table entry which corresponds to the specified indexValue.
	 * @param caseIndexValue index value for specific case
	 * @return table entry address
	 */
	@Override
	Address getCaseAddress(int caseIndexValue) {
		AddressSpace space = tableBase.getAddressSpace();
		return tableBase.add(caseIndexValue * tableOffset.getTableEntrySize() *
			space.getAddressableUnitSize());
	}

	/**
	 * Returns table entry size in bytes
	 */
	int getTableEntrySize() {
		return tableOffset.getTableEntrySize();
	}

	/**
	 * Returns Varnode or VarnodeOperation which corresponds to 
	 * the index value which identifies the switch case.
	 */
	@Override
	Varnode getIndexValue() {
		return tableOffset.getIndexValue();
	}

	/**
	 * Qualify VarnodeOperation as INT_ADD(constant-table-address, computed-table-offset)
	 * and return TableEntryAddress if qualified or null if not.
	 * @param addrFactory
	 * @param v potential input value which corresponds to a switch table entry address
	 * @return TableEntryAddress object or null if v failed qualification
	 */
	static TableEntryAddress getTableEntryAddress(AddressFactory addrFactory, Varnode v) {
		if (!(v instanceof VarnodeOperation)) {
			return null;
		}
		VarnodeOperation tableEntryAddressComputation = (VarnodeOperation) v;
		if (tableEntryAddressComputation.getPCodeOp().getOpcode() != PcodeOp.INT_ADD) {
			return null;
		}
		Address tableBase = null;
		ComputedTableOffset tableOffset = null;
		Varnode[] inputValues = tableEntryAddressComputation.getInputValues();
		if (inputValues[0].isConstant()) {
			tableBase = getAddress(addrFactory, inputValues[0].getOffset());
			tableOffset = ComputedTableOffset.getComputedTableOffset(inputValues[1]);
		}
		else if (inputValues[1].isConstant()) {
			tableBase = getAddress(addrFactory, inputValues[1].getOffset());
			tableOffset = ComputedTableOffset.getComputedTableOffset(inputValues[0]);
		}
		if (tableBase == null || tableOffset == null) {
			return null; // does not qualify
		}
		return new TableEntryAddress(tableBase, tableOffset);
	}

	private static Address getAddress(AddressFactory addrFactory, long offset) {
		try {
			return addrFactory.getDefaultAddressSpace().getAddress(offset);
		}
		catch (AddressOutOfBoundsException e) {
		}
		return null;
	}

}
