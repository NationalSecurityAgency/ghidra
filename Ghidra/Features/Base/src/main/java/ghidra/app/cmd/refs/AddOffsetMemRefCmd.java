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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

/**
 * Command class to add an offset memory reference to the program.
 */
public class AddOffsetMemRefCmd implements Command<Program> {

	private Address fromAddr;
	private Address toAddr;
	private boolean toAddrIsBase;
	private RefType refType;
	private SourceType source;
	private int opIndex;
	private long offset;

	/**
	 * Command constructor for adding an offset memory reference. The first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.  If toAddr corresponds to
	 * the EXTERNAL memory block (see {@link MemoryBlock#EXTERNAL_BLOCK_NAME}) the
	 * resulting offset reference will report to/base address as the same
	 * regardless of specified offset.
	 * @param fromAddr address of the codeunit where the reference occurs
	 * @param toAddr address of the location being referenced.
	 * @param toAddrIsBase if true toAddr is treated as base address, else treated as (base+offet).
	 * It is generally preferred to specify as a base address to ensure proper handling of
	 * EXTERNAL block case.
	 * @param refType reference type - how the location is being referenced.
	 * @param source the source of the reference
	 * @param opIndex the operand index in the code unit where the reference occurs 
	 * @param offset value added to a base address to get the toAddr
	 */
	public AddOffsetMemRefCmd(Address fromAddr, Address toAddr, boolean toAddrIsBase,
			RefType refType, SourceType source, int opIndex, long offset) {
		this.fromAddr = fromAddr;
		this.toAddr = toAddr;
		this.toAddrIsBase = toAddrIsBase;
		this.refType = refType;
		this.source = source;
		this.opIndex = opIndex;
		this.offset = offset;
	}

	@Override
	public boolean applyTo(Program program) {
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addOffsetMemReference(fromAddr, toAddr, toAddrIsBase, offset, refType, source,
			opIndex);
		return true;
	}

	@Override
	public String getStatusMsg() {
		return "";
	}

	@Override
	public String getName() {
		return "Add Offset Memory Reference";
	}

}
