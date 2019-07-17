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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable;

import java.util.*;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Defines the follow-on behavior of how to handle an exception in the context
 * of the exceptions' C++ type.
 */
public class LSDAActionTable {

	/* Class Members */
	private TaskMonitor monitor;
	private Program program;
	private RegionDescriptor region;

	private Address tableAddress;
	private Address nextAddress;

	private List<LSDAActionRecord> records = new ArrayList<>();

	/**
	 * Constructor for an action table.
	 * <br>Note: The <code>create(Address)</code> method must be called after constructing an 
	 * LSDAActionTable to associate it with an address before any of its "get..." methods are called.
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the action table.
	 * @param region the region or section of the program containing the action table.
	 */
	public LSDAActionTable(TaskMonitor monitor, Program program, RegionDescriptor region) {
		this.monitor = monitor;
		this.program = program;
		this.region = region;
	}

	/**
	 * Create an LSDA Action Table from the bytes at <code>address</code>.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param address the start (minimum address) of this action table.
	 * @param maxddress the end (maximum address) of this action table.
	 */
	public void create(Address address, Address maxAddress) {

		if (address == null) {
			throw new IllegalArgumentException("action record's address cannot be null.");
		}
		if (monitor.isCancelled()) {
			return;
		}

		tableAddress = address;

		monitor.setMessage("Creating LSDA Action Table");

		LSDAActionRecord rec = null;
		
		while (address.compareTo(maxAddress) <= 0) {
			rec = new LSDAActionRecord(monitor, program, region, this);
			rec.create(address);

			records.add(rec);

			address = rec.getNextAddress();
		}

		nextAddress = address;

		SetCommentCmd commentCmd =
			new SetCommentCmd(tableAddress, CodeUnit.PLATE_COMMENT, "(LSDA) Action Table");
		commentCmd.applyTo(program);
	}

	/**
	 * Gets the base address (minimum address) indicating the start of this action table.
	 * @return the address of this action table or null if this action table hasn't been 
	 * created at any address yet.
	 */
	Address getAddress() {
		return tableAddress;
	}

	/**
	 * Gets the next address indicating the address after this action table.
	 * @return the next address after this action table or null if this action table hasn't been 
	 * created at any address yet.
	 */
	Address getNextAddress() {
		return nextAddress;
	}

	/**
	 * Gets all of the action records in this action table.
	 * @return the action records in this table or empty if no address has been established for 
	 * this table.
	 */
	public List<LSDAActionRecord> getActionRecords() {
		return Collections.unmodifiableList(records);
	}

	/**
	 * Gets the action record from the table by its index. 
	 * @param actionIndex indicates which action record (0 based) to get from the table.
	 * @return the action record or null if the index is invalid or an address hasn't been 
	 * established for this table yet.
	 */
	public LSDAActionRecord getActionRecord(int actionIndex) {
		actionIndex -= 1;
		if (actionIndex < 0) {
			return null;
		}
		return records.get(actionIndex);
	}

	/**
	 * Gets the action record from the table for the indicated offset.
	 * @param actionOffset the byte offset into the table for the desired record
	 * @return the action record for the specified offset or null
	 */
	public LSDAActionRecord getActionRecordAtOffset(int actionOffset) {
		// "records" is a list of action table records that were added in order min to max.
		int currentOffset = 0;
		for (LSDAActionRecord lsdaActionRecord : records) {
			int size = lsdaActionRecord.getSize();
			int nextOffset = currentOffset + size;
			if (actionOffset >= currentOffset && actionOffset < nextOffset) {
				return lsdaActionRecord;
			}
			currentOffset = nextOffset;
		}
		return null; // didn't find it.
	}

}
