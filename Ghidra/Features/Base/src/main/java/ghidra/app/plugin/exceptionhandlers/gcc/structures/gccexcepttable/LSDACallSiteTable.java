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

import java.util.*;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Defines the specific program regions that may throw an exception within the 
 * context of the LSDA.
 */
public class LSDACallSiteTable extends GccAnalysisClass {

	/* Class Members */
	private AddressRange bounds;

	private Address nextAddress;

	private RegionDescriptor region;
	private List<LSDACallSiteRecord> records = new ArrayList<>();

	/**
	 * Constructor for a call site table.
	 * <br>Note: The <code>create(Address)</code> method must be called after constructing an 
	 * LSDACallSiteTable to associate it with an address before any of its "get..." methods are called.
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the call site table.
	 * @param region the region of the program associated with the call site table.
	 */
	public LSDACallSiteTable(TaskMonitor monitor, Program program, RegionDescriptor region) {
		super(monitor, program);
		this.region = region;
	}

	/**
	 * Create a LSDA Call Site Table from the bytes at <code>addr</code>.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param addr the start (minimum address) of this call site table.
	 * @throws MemoryAccessException if memory couldn't be accessed for the call site table
	 */
	public void create(Address addr) throws MemoryAccessException {

		records.clear();

		/* use current program location if 'addr' is null */
		if (addr == null || monitor.isCancelled()) {
			return;
		}

		LSDAHeader header = region.getLSDATable().getHeader();

		if (header.getCallSiteTableLength() <= 0) {
			return;
		}

		Address baseAddr = addr;
		monitor.setMessage("Creating GCC LSDA Call Site Table ");

		SetCommentCmd commentCmd =
			new SetCommentCmd(baseAddr, CodeUnit.PLATE_COMMENT, "(LSDA) Call Site Table");
		commentCmd.applyTo(program);

		Address limit = baseAddr.add(header.getCallSiteTableLength() - 1);

		DwarfEHDecoder callSiteDecoder =
			DwarfDecoderFactory.getDecoder(header.getCallSiteTableEncoding());

		long remain = limit.subtract(addr);

		do {
			LSDACallSiteRecord rec = new LSDACallSiteRecord(monitor, program, region);
			rec.create(addr, callSiteDecoder);

			verifyCallSiteRecord(rec);

			records.add(rec);

			addr = rec.getNextAddress();
			remain = limit.subtract(addr);

		}
		while (remain > 0);

		bounds = new AddressRangeImpl(baseAddr, baseAddr.add(header.getCallSiteTableLength()));

		nextAddress = addr;
	}

	/**
	 * Gets the end address of this call site table.
	 * @return the table's end address.
	 */
	Address getTableEndAddress() {
		return bounds.getMaxAddress();
	}

	/**
	 * Gets the next address indicating the address after this call site table.
	 * @return the next address after this call site table or null if this table hasn't been 
	 * created at any address yet.
	 */
	Address getNextAddress() {
		return nextAddress;
	}

	/**
	 * Gets all of the call site records in this table.
	 * @return the call site records in this table or empty if no address has been established for 
	 * this table.
	 */
	public List<LSDACallSiteRecord> getCallSiteRecords() {
		return Collections.unmodifiableList(records);
	}

	private static boolean contains(AddressRange container, AddressRange child) {
		return container.getMinAddress().compareTo(child.getMinAddress()) <= 0 &&
			container.getMaxAddress().compareTo(child.getMaxAddress()) >= 0;
	}

	private void verifyCallSiteRecord(LSDACallSiteRecord rec) {
		AddressRange body = region.getRange();

		boolean containsCallSite = contains(body, rec.getCallSite());
		boolean containsLandingPad = body.contains(rec.getLandingPad());

		if (containsCallSite && containsLandingPad) {
			return;
		}
		if (!containsCallSite) {
			Msg.error(this, "Function body does not fully contain the call site area");
		}
		if (!containsLandingPad) {
			Msg.error(this, "Function body does not contain the landing pad");
		}
	}

}
