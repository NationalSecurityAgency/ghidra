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


public abstract class Switch {
	

	/**
	 * Returns address corresponding to the specified caseIndexValue.
	 * @param caseIndexValue index value for specific case
	 * @return case address
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 */
	abstract Address getCaseAddress(int caseIndexValue) throws MemoryAccessException, AddressOutOfBoundsException;
	
	/**
	 * Returns the Varnode or VarnodeOperation which corresponds to the case index value for a switch.
	 */
	abstract Varnode getIndexValue();
	
	/**
	 * Qualify IndirectJumpSwitch
	 * and return IndirectJumpSwitch object if qualified or null if not.
	 * @param program
	 * @param v potential input value which corresponds to a indirect destination
	 * @return IndirectJumpSwitch object or null if v failed qualification
	 */
	static Switch getIndirectJumpSwitch(Program program, Varnode v) {
		if (!(v instanceof VarnodeOperation)) {
			return null;
		}
		VarnodeOperation op = (VarnodeOperation)v;
		int opcode = op.getPCodeOp().getOpcode();
		if (opcode == PcodeOp.LOAD) {
			// Absolute address jump table
			TableEntry tableEntry = TableEntry.getTableEntry(program, op);
			if (tableEntry != null) {
				return tableEntry;
			}
			return null;
		}
		if (opcode == PcodeOp.INT_ADD) {
			// Relative jump offset table 
			RelativeJumpTableSwitch relJumpTableSwitch = RelativeJumpTableSwitch.getRelativeJumpTableSwitch(program, op);
			if (relJumpTableSwitch != null) {
				return relJumpTableSwitch;
			}
			// Relative computed offset (fixed case size - e.g., PIC processors)
			return TableEntryAddress.getTableEntryAddress(program.getAddressFactory(), op);
		}
		return null;
	}

	
	
}
