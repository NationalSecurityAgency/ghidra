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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Stores addresses of __type_info structures for thrown values. Used by the Unwind routines
 * to determine if a given catch block appropriately handles a given exception-of-type. 
 */
public class LSDATypeTable extends GccAnalysisClass {

	/* Class Members */
	private RegionDescriptor region;

	private Address nextAddress;

	private List<Address> typeInfoAddrs = new ArrayList<>(2);

	/**
	 * Constructor for a table of references to types that are associated with catch actions.
	 * <br>Note: The <code>create(Address, Address)</code> method must be called after constructing 
	 * an LSDATypeTable to associate it with an address before any of its "get..." methods 
	 * are called.
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the type table.
	 * @param region the region of the program associated with this type table.
	 */
	public LSDATypeTable(TaskMonitor monitor, Program program, RegionDescriptor region) {
		super(monitor, program);
		this.region = region;
	}

	/**
	 * Create a LSDA Type Table from the bytes between <code>bottom</code> and <code>top</code>. 
	 * This table is built from bottom-to-top.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param bottom the bottom address of the type table
	 * @param top the top address of the type table
	 */
	public void create(Address bottom, Address top) {

		if (bottom == null || top == null || monitor.isCancelled()) {
			return;
		}

		monitor.setMessage("Creating LSDA Type Table");

		int encoding = region.getLSDATable().getHeader().getTTypeEncoding();
		DwarfEHDecoder decoder = DwarfDecoderFactory.getDecoder(encoding);

		DataType encodedDt = decoder.getDataType(program);
		int stride = decoder.getDecodeSize(program);

		String comment = "Type Reference";

		top = align4(top);

		Address addr = bottom.subtract(stride - 1);

		while (addr.compareTo(top) >= 0) {
			DwarfDecodeContext ctx = new DwarfDecodeContext(program, addr);

			try {
				Address typeRef = decoder.decodeAddress(ctx);

				typeInfoAddrs.add(typeRef);

				createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);

				if (typeRef.getOffset() != 0) {
					program.getReferenceManager().addMemoryReference(addr, typeRef, RefType.DATA,
						SourceType.ANALYSIS, 0);
				}

			}
			catch (MemoryAccessException mae) {
				SetCommentCmd commentCmd =
					new SetCommentCmd(addr, CodeUnit.EOL_COMMENT, "Unable to resolve pointer");
				commentCmd.applyTo(program);
			}

			addr = addr.subtract(stride);
		}

		SetCommentCmd commentCmd =
			new SetCommentCmd(top, CodeUnit.PLATE_COMMENT, "(LSDA) Type Table");
		commentCmd.applyTo(program);

		nextAddress = bottom.add(1);
	}

	private Address align4(Address addr) {

		int incr = 4 - ((int) addr.getOffset() & 0x3);
		if (incr == 4) {
			return addr;
		}

		createAndCommentData(program, addr, new ArrayDataType(new ByteDataType(), incr, 1),
			" -- alignment pad", CodeUnit.EOL_COMMENT);

		return addr.add(incr);

	}

	/**
	 * Gets the address of the type information from the reference record at the specified index in 
	 * the table.
	 * @param index the index (1-based) of the type info table record.
	 * @return the address of the type info.
	 */
	public Address getTypeInfoAddress(int index) {
		if (index <= 0 || index > typeInfoAddrs.size()) {
			return Address.NO_ADDRESS;
		}
		return typeInfoAddrs.get(index - 1); // Adjust since the array is 0 based.
	}

	/**
	 * Gets the address after this type table.
	 * @return the next address after this type table or null if this type table hasn't been 
	 * created at any address yet.
	 */
	public Address getNextAddress() {
		return nextAddress;
	}
}
