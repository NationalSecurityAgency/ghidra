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
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.UnsignedLeb128DataType;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Defines the bounds of a try-catch region.
 */
public class LSDACallSiteRecord extends GccAnalysisClass {

	/* Class Members */
	private RegionDescriptor region;

	private Address nextAddress;

	private long callSitePosition;
	private long callSiteLength;

	private long landingPadOffset;
	private int actionOffset;

	private AddressRange callSiteRange;
	private Address landingPadAddr;

	/**
	 * Constructor for a call site record.
	 * <br>Note: The <code>create(Address)</code> method must be called after constructing an 
	 * LSDACallSiteRecord to associate it with an address before any of its "get..." methods are 
	 * called.
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the call site record.
	 * @param region the region of the program associated with the call site record.
	 */
	public LSDACallSiteRecord(TaskMonitor monitor, Program program, RegionDescriptor region) {
		super(monitor, program);
		this.region = region;
	}

	/**
	 * Creates data for a call site record at the indicated address and creates a comment to 
	 * identify it as a call site record.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param addr the start (minimum address) of this call site record.
	 * @param decoder decodes dwarf encoded information within the LSDA
	 * @throws MemoryAccessException if memory couldn't be accessed for the call site record
	 */
	public void create(Address addr, DwarfEHDecoder decoder) throws MemoryAccessException {

		/* use current program location if 'addr' is null */
		if (addr == null || monitor.isCancelled())
			return;

		Address baseAddr = addr;
		monitor.setMessage("Creating LSDA Call Site Record");

		Address callSiteDataAddr = addr;
		addr = createCallSitePosition(addr, decoder);
		addr = createCallSiteLength(addr, decoder);
		Address lpDataAddr = addr;
		addr = createLandingPad(addr, decoder);

		addr = createAction(addr);

		Address lpStart = region.getLSDATable().getHeader().getLPStartAddress();

		Address callSiteBaseAddr = lpStart.add(getCallSitePosition());
		Address callSiteExtentAddr = callSiteBaseAddr.add(getCallSiteLength() - 1);

		callSiteRange = new AddressRangeImpl(callSiteBaseAddr, callSiteExtentAddr);

		landingPadAddr = lpStart.add(getLandingPadOffset());

		SetCommentCmd commentCmd =
			new SetCommentCmd(baseAddr, CodeUnit.PLATE_COMMENT, "(LSDA) Call Site Record");
		commentCmd.applyTo(program);

		if (program.getMemory().contains(callSiteBaseAddr)) {
			program.getReferenceManager().addMemoryReference(callSiteDataAddr, callSiteBaseAddr,
				RefType.DATA, SourceType.ANALYSIS, 0);
		}

		if (program.getMemory().contains(landingPadAddr)) {
			program.getReferenceManager().addMemoryReference(lpDataAddr, landingPadAddr,
				RefType.DATA, SourceType.ANALYSIS, 0);
		}

		nextAddress = addr;
	}

	private Address createCallSitePosition(Address addr, DwarfEHDecoder decoder)
			throws MemoryAccessException {
		String comment = "(LSDA Call Site) IP Offset";

		DwarfDecodeContext ctx = new DwarfDecodeContext(program, addr);

		callSitePosition = decoder.decode(ctx);

		int encodedLen = ctx.getEncodedLength();

		DataType encodedDt = decoder.getDataType(program);

		createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);

		return addr.add(encodedLen);
	}

	private Address createCallSiteLength(Address addr, DwarfEHDecoder decoder)
			throws MemoryAccessException {
		String comment = "(LSDA Call Site) IP Range Length";

		DwarfDecodeContext ctx = new DwarfDecodeContext(program, addr);

		callSiteLength = decoder.decode(ctx);

		int encodedLen = ctx.getEncodedLength();

		DataType encodedDt = decoder.getDataType(program);

		createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);

		return addr.add(encodedLen);
	}

	private Address createLandingPad(Address addr, DwarfEHDecoder decoder)
			throws MemoryAccessException {
		String comment = "(LSDA Call Site) Landing Pad Address";

		DwarfDecodeContext ctx = new DwarfDecodeContext(program, addr);

		landingPadOffset = decoder.decode(ctx);

		int encodedLen = ctx.getEncodedLength();

		DataType encodedDt = decoder.getDataType(program);

		createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);

		return addr.add(encodedLen);
	}

	private Address createAction(Address addr) {
		String comment = "(LSDA Call Site) Action Table Offset";

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);

		int encodedLen = uleb.getLength(buf, -1);

		Object actionObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

		actionOffset = (int) ((Scalar) actionObj).getUnsignedValue();
		encodedLen = ((Scalar) actionObj).bitLength() / 8;

		if (actionOffset == 0) {
			comment += " (No action -- cleanup)";
		}

		createAndCommentData(program, addr, uleb, comment, CodeUnit.EOL_COMMENT);
		return addr.add(encodedLen);
	}

	/**
	 * Gets the next address indicating the address after this call site record.
	 * @return the next address after this call site record or null if this record hasn't been 
	 * created at any address yet.
	 */
	Address getNextAddress() {
		return nextAddress;
	}

	private long getCallSitePosition() {
		return callSitePosition;
	}

	/**
	 * Get the call site addresses which make up the <code>try</code>.
	 * @return the address range of the call site
	 */
	public AddressRange getCallSite() {
		return callSiteRange;
	}

	private long getCallSiteLength() {
		return callSiteLength;
	}

	/**
	 * Get the landing pad address which indicates the <code>catch</code> for this call site.
	 * @return the landing pad address of the catch.
	 */
	public Address getLandingPad() {
		return landingPadAddr;
	}

	/**
	 * Gets the offset of the landing pad address from the landing pad start.
	 * @return the landing pad offset
	 */
	public long getLandingPadOffset() {
		return landingPadOffset;
	}

	/**
	 * Get the offset into the action table for the first action record to be caught.
	 * @return the offset into the action table
	 */
	public int getActionOffset() {
		return actionOffset;
	}

}
