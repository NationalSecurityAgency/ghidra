/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.state.VarnodeOperation;

public class RelativeJumpTableSwitch extends Switch {

	private final Address jumpBase;
	private final TableEntry offset;

	public RelativeJumpTableSwitch(Address jumpBase, TableEntry offset) {
		this.jumpBase = jumpBase;
		this.offset = offset;
	}

	@Override
	Address getCaseAddress(int caseIndexValue) throws MemoryAccessException,
			AddressOutOfBoundsException {
		long displacement = offset.getTableEntryValue(caseIndexValue, 1, false);
		return jumpBase.add(displacement);
	}

	@Override
	Varnode getIndexValue() {
		return offset.getIndexValue();
	}

	static RelativeJumpTableSwitch getRelativeJumpTableSwitch(Program program, VarnodeOperation op) {
		if (op.getPCodeOp().getOpcode() != PcodeOp.INT_ADD) {
			return null;
		}
		AddressFactory addrFactory = program.getAddressFactory();
		Address jumpBase = null;
		TableEntry offset = null;
		Address opAddr = op.getPCodeOp().getSeqnum().getTarget();
		Varnode[] inputValues = op.getInputValues();
		if (inputValues[0].isConstant()) {
			jumpBase = getAddress(addrFactory, inputValues[0].getOffset(), opAddr);
			offset = TableEntry.getTableEntry(program, inputValues[1]);
		}
		else if (inputValues[1].isConstant()) {
			jumpBase = getAddress(addrFactory, inputValues[1].getOffset(), opAddr);
			offset = TableEntry.getTableEntry(program, inputValues[0]);
		}
		if (jumpBase == null || offset == null) {
			return null; // does not qualify
		}
		return new RelativeJumpTableSwitch(jumpBase, offset);
	}

	private static Address getAddress(AddressFactory addrFactory, long offset, Address closeToAddr) {
		try {
			Address addr = addrFactory.getDefaultAddressSpace().getAddress(offset);
			long distance = addr.subtract(closeToAddr);
			if (distance > -128 && distance < 128) {
				// require switch to be relative to some nearby address
				return addr;
			}
		}
		catch (AddressOutOfBoundsException e) {
		}
		return null;
	}

}
