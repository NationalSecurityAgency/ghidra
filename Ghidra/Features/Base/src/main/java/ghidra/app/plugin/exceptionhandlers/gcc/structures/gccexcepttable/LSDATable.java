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

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * The Language Specific Data Area (LSDA) serves as a reference to the runtime for how to 
 * respond to an exception. Each function that handles an exception (that is, has a 'catch' 
 * block) has an LSDA, and each exception-prone fragment has a record within the LSDA.
 * The runtime will walk up the call stack as part of the Unwind routines, asking the LSDA 
 * if a function knows how to handle the thrown exception;the default handler typically 
 * terminates the program. 
 * <p>
 * Unwind uses the personality function and the LSDA -- the return value tells Unwind whether 
 * the function can handle the exception or not.
 * <p>
 *   The LSDA is comprised of:
 *   <ul>
 *   <li>A header that describes the bounds of exception handling support and encoding
 *     modes for values found later in the LSDA table
 *   <li>A call site table that describes each location a 'throws' occurs and where
 *     a corresponding catch block resides, and the actions to take.
 *   <li>An action table, that describes what the runtime needs to do during unwind
 *   </ul>
 * <p>  
 * The structures modeled here are described in detail in the C++ ABI.
 */

public class LSDATable {

	/* Class Members */
	private TaskMonitor monitor;
	private Program program;

	private LSDAHeader header;
	private LSDACallSiteTable callSiteTable;
	private LSDAActionTable actionTable;
	private LSDATypeTable typeTable;

	/**
	 * Constructor for an LSDA exception table.
	 * <br>Note: The <code>create(Address, DwarfEHDecoder, RegionDescriptor)</code> method must be 
	 * called after constructing an LSDATable to associate it with an address before any of 
	 * its "get..." methods are called.
	 * @param monitor task monitor to see if the user has cancelled analysis
	 * @param program the program containing the table
	 */
	public LSDATable(TaskMonitor monitor, Program program) {
		this.monitor = monitor;
		this.program = program;
	}

	/**
	 * Create a LSDA Table from the bytes at <code>addr</code>. Parses the header, call site table,
	 * action table, and type table.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param tableAddr the start (minimum address) of this LSDA table.
	 * @param region the region of the program associated with this table
	 * @throws MemoryAccessException if memory couldn't be accessed for the LSDA table
	 */
	public void create(Address tableAddr, RegionDescriptor region)
			throws MemoryAccessException {

		region.setLSDATable(this);

		Address baseAdress = tableAddr;

		header = new LSDAHeader(monitor, program, region);
		header.create(tableAddr);

		tableAddr = header.getNextAddress();

		callSiteTable = new LSDACallSiteTable(monitor, program, region);
		callSiteTable.create(tableAddr);

		tableAddr = callSiteTable.getNextAddress();

		int maxActionOffset = 0;
		boolean generateActionTable = false;
		for (LSDACallSiteRecord cs : callSiteTable.getCallSiteRecords()) {
			maxActionOffset = Math.max(maxActionOffset, cs.getActionOffset());
			if (cs.getActionOffset() != LSDAActionRecord.NO_ACTION) {
				generateActionTable = true;
			}
		}

		if (generateActionTable) {

			Address maxTableAddr = tableAddr.add(maxActionOffset);

			actionTable = new LSDAActionTable(monitor, program, region);
			actionTable.create(tableAddr, maxTableAddr);

			tableAddr = actionTable.getNextAddress();
		}

		if (header.getTTypeEncoding() != LSDAHeader.OMITTED_ENCODING_TYPE) {

			// NOTICE: This builds from the bottom (TTypeBaseAddress) to top
			// (tableAddr)
			Address tTypeBaseAddress = header.getTTypeBaseAddress();
			if (tTypeBaseAddress != Address.NO_ADDRESS) {
				typeTable = new LSDATypeTable(monitor, program, region);
				typeTable.create(tTypeBaseAddress, tableAddr);
			}
		}

		SetCommentCmd commentCmd = new SetCommentCmd(baseAdress, CodeUnit.PLATE_COMMENT, "Language-Specific Data Area");
		commentCmd.applyTo(program);

	}

	/**
	 * @return the LSDA header
	 */
	LSDAHeader getHeader() {
		return header;
	}

	/**
	 * @return the call site table for this LSDA
	 */
	public LSDACallSiteTable getCallSiteTable() {
		return callSiteTable;
	}

	/**
	 * @return the action table for this LSDA
	 */
	public LSDAActionTable getActionTable() {
		return actionTable;
	}

	/**
	 * @return the type table for this LSDA
	 */
	public LSDATypeTable getTypeTable() {
		return typeTable;
	}

}
