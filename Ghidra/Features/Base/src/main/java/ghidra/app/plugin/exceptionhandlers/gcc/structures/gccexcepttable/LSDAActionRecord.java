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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.app.util.bin.LEB128Info;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.SignedLeb128DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * A record that associates the type info with a catch action.
 */
public class LSDAActionRecord extends GccAnalysisClass {

	public static final long NO_ACTION = 0;

	/* Class Members */
	private final LSDAActionTable lsdaActionTable;

	private Address recordAddress;
	private Address nextAddress;

	private int typeFilter;
	private int displacementToNext;
	private Address nextActionAddress;
	private int size = 0;

	/**
	 * Constructor for an action record.
	 * <br>Note: The <code>create(Address)</code> method must be called after constructing an 
	 * LSDAActionRecord to associate it with an address before any of its "get..." methods are called.
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the action record.
	 * @param region the region of the program associated with the action record.
	 * @param lsdaActionTable the action table containing the action record.
	 */
	public LSDAActionRecord(TaskMonitor monitor, Program program, RegionDescriptor region,
			LSDAActionTable lsdaActionTable) {
		super(monitor, program);
		this.lsdaActionTable = lsdaActionTable;
	}

	/**
	 * Creates data for an action record at the indicated address and creates a comment to identify
	 * it as an action record.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param address the start (minimum address) of this action record.
	 * @throws MemoryAccessException 
	 */
	public void create(Address address) throws MemoryAccessException {

		if (address == null) {
			throw new IllegalArgumentException("action record's address cannot be null.");
		}
		if (monitor.isCancelled()) {
			return;
		}
		this.recordAddress = address;

		Address addr = address;
		size = 0;

		addr = createTypeFilter(addr);

		addr = createNextActionRef(addr);

		SetCommentCmd commentCmd =
			new SetCommentCmd(address, CommentType.PLATE, "(LSDA) Action Record");
		commentCmd.applyTo(program);

		nextAddress = addr;
	}

	private Address createTypeFilter(Address addr) throws MemoryAccessException {

		String comment = "(LSDA Action Table) Type Filter";

		LEB128Info sleb128 = GccAnalysisUtils.readSLEB128Info(program, addr);

		typeFilter = (int) sleb128.asLong();

		createAndCommentData(program, addr, SignedLeb128DataType.dataType, comment,
			CommentType.EOL);

		size += sleb128.getLength();

		return addr.add(sleb128.getLength());
	}

	private Address createNextActionRef(Address addr) throws MemoryAccessException {
		String comment = "(LSDA Action Table) Next-Action Reference";

		LEB128Info sleb128 = GccAnalysisUtils.readSLEB128Info(program, addr);

		displacementToNext = (int) sleb128.asLong();

		if (displacementToNext == 0) {
			nextActionAddress = Address.NO_ADDRESS;
		}
		else {
			nextActionAddress = addr.add(displacementToNext);
		}

		createAndCommentData(program, addr, SignedLeb128DataType.dataType, comment,
			CommentType.EOL);

		size += sleb128.getLength();

		return addr.add(sleb128.getLength());
	}

	/**
	 * Gets the filter value indicating which type is associated with this action record.
	 * @return the value for this action's type.
	 */
	public int getActionTypeFilter() {
		return typeFilter;
	}

	/**
	 * Gets the base address of the next action record to consider in the action table.
	 * @return the address of the next action record or null.
	 */
	public Address getNextActionAddress() {
		return nextActionAddress;
	}

	/**
	 * Gets the next address indicating the address after this action record.
	 * @return the next address after this action record or null if this action record hasn't been 
	 * created at any address yet.
	 */
	public Address getNextAddress() {
		return nextAddress;
	}

	/**
	 * Gets the base address (minimum address) indicating the start of this action record.
	 * @return the address of this action record or null if this action record hasn't been 
	 * created at any address yet.
	 */
	public Address getAddress() {
		return recordAddress;
	}

	/**
	 * Gets the record for the next action that the catch should fall to if the type isn't 
	 * the one for this action.
	 * @return the next action's record or null if there isn't another specific type of 
	 * exception for this try.
	 */
	public LSDAActionRecord getNextAction() {
		Address recAddr = getNextActionAddress();
		if (lsdaActionTable.getAddress().equals(recAddr)) {
			return null;
		}
		if (recAddr == Address.NO_ADDRESS) {
			return null;
		}

		for (LSDAActionRecord rec : lsdaActionTable.getActionRecords()) {
			if (rec.getAddress().equals(recAddr)) {
				return rec;
			}
		}
		throw new IllegalArgumentException("Invalid action table record address");

	}

	/**
	 * Gets the size of the action record or 0 if this action record hasn't been created at any 
	 * address yet.
	 * @return the size of the action record or 0;
	 */
	public int getSize() {
		return size;
	}
}
