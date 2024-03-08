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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Command class to add a shifted memory reference to the program.
 */
public class AddShiftedMemRefCmd implements Command<Program> {

	private Address fromAddr;
	private Address toAddr;
	private RefType refType;
	private SourceType source;
	private int opIndex;
	private int shift;

	/**
	 * Command constructor for adding a shifted memory reference
	 * @param fromAddr address of the codeunit where the reference occurs
	 * @param toAddr computed as the value of the operand at opIndex shifted
	 * by the number of bits specified by shiftValue 
	 * @param refType reference type - how the location is being referenced.
	 * @param source the source of the reference
	 * @param opIndex the operand index in the code unit where the reference occurs 
	 * @param shift the number of bits to shift the value by
	 */
	public AddShiftedMemRefCmd(Address fromAddr, Address toAddr, RefType refType, SourceType source,
			int opIndex, int shift) {
		this.fromAddr = fromAddr;
		this.toAddr = toAddr;
		this.refType = refType;
		this.source = source;
		this.opIndex = opIndex;
		this.shift = shift;
	}

	@Override
	public boolean applyTo(Program program) {
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addShiftedMemReference(fromAddr, toAddr, shift, refType, source, opIndex);
		return true;
	}

	@Override
	public String getStatusMsg() {
		return "";
	}

	@Override
	public String getName() {
		return "Add Shifted Memory Reference";
	}

}
