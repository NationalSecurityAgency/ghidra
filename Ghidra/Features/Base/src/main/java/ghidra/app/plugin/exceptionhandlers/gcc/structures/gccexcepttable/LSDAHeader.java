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
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Defines the bounds of exception unwinding support, within a function, 
 * and unwind procedures.
 * * lpStartAddr is the program address where support begins. This value is 
 *   encoded according to lpStartEncoding.
 * * ttypeAddr is the location-relative program address, encoded per 
 *   ttypeEncoding, of the associated C++ types table (types of thrown values).
 */
public class LSDAHeader extends GccAnalysisClass {

	static final int OMITTED_ENCODING_TYPE = 0xFF;

	/* Class Members */
	private RegionDescriptor region;

	private static final int BYTE_LEN = new ByteDataType().getLength();

	private int lpStartEncoding = 0xFF;
	private Address lpStartAddr;

	private boolean hasTypeTable = false;
	private int ttypeEncoding = OMITTED_ENCODING_TYPE;
	private long ttypeOffset;
	private Address ttypeAddr = Address.NO_ADDRESS;

	private byte callSiteTableEncoding = (byte) OMITTED_ENCODING_TYPE;
	private int callSiteTableLength = 0;

	private long headerSize = 0;
	private AddressRange tableBounds = null;

	private Address nextAddress;

	private static final int LPSTART_PTR_TYPETABLE_FLAG = 0x01;

	private int curSize = 0;
	private long callSiteTableHeaderSize;

	/**
	 * Constructor for the LSDA header which indicates encoding for the LSDA tables.
	 * <br>Note: The <code>create(Address)</code> method must be called after constructing an 
	 * LSDAHeader to associate it with an address before any of its "get..." methods are called.
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing this header.
	 * @param region the region of the program associated with this header.
	 */
	public LSDAHeader(TaskMonitor monitor, Program program, RegionDescriptor region) {
		super(monitor, program);
		this.region = region;
	}

	private Address createLPStartEncoding(Address addr) throws MemoryAccessException {

		String comment = "(LSDA) LPStart Encoding";
		createAndCommentData(program, addr, new DwarfEncodingModeDataType(), comment,
			CodeUnit.EOL_COMMENT);
		lpStartEncoding = GccAnalysisUtils.readByte(program, addr);

		curSize += BYTE_LEN;
		return addr.add(BYTE_LEN);
	}

	private static Address makeAddress(Program program, long offset) {
		AddressFactory addrFactory = program.getAddressFactory();
		AddressSpace ram = addrFactory.getDefaultAddressSpace();

		return addrFactory.getAddress(ram.getSpaceID(), offset);
	}

	private Address createLPStartPointer(Address addr) throws MemoryAccessException {
		String comment = "(LSDA) LPStart Offset";

		DwarfEHDecoder decoder = DwarfDecoderFactory.getDecoder(lpStartEncoding);
		if (decoder.getDataFormat() == DwarfEHDataDecodeFormat.DW_EH_PE_omit) {
			lpStartAddr = region.getRangeStart();
			return addr;
		}

		DwarfDecodeContext ctx = new DwarfDecodeContext(program, addr, region.getRangeStart());

		long raw = decoder.decode(ctx);

		// the bottom 4 bits are *not* part of the pointer
		long controls = raw & 0x0F;
		raw |= 0xF;
		lpStartAddr = makeAddress(program, raw);

		hasTypeTable = (controls & LPSTART_PTR_TYPETABLE_FLAG) == LPSTART_PTR_TYPETABLE_FLAG;

		int encodedLen = ctx.getEncodedLength();

		DataType encodedDt = decoder.getDataType(program);

		createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);

		curSize += encodedLen;
		return addr.add(encodedLen);
	}

	private Address createTTypeEncoding(Address addr) throws MemoryAccessException {
		String comment = "(LSDA) TType Encoding";

		ttypeEncoding = GccAnalysisUtils.readByte(program, addr);

		createAndCommentData(program, addr, new DwarfEncodingModeDataType(), comment,
			CodeUnit.EOL_COMMENT);

		curSize += BYTE_LEN;
		return addr.add(BYTE_LEN);
	}

	private Address createTTypeOffset(Address addr) {
		String comment = "(LSDA) TType Offset";

		DwarfEHDecoder decoder = DwarfDecoderFactory.getDecoder(ttypeEncoding);
		if (decoder.getDataFormat() == DwarfEHDataDecodeFormat.DW_EH_PE_omit) {
			ttypeOffset = 0;
			return addr;
		}

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);

		int encodedLen = uleb.getLength(buf, -1);

		Object actionObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

		// this offset it based from *here*..
		ttypeOffset = (int) ((Scalar) actionObj).getUnsignedValue() + curSize;

		createAndCommentData(program, addr, uleb, comment, CodeUnit.EOL_COMMENT);

		return addr.add(encodedLen);
	}

	private Address createCallSiteTableEncoding(Address addr) throws MemoryAccessException {
		String comment = "(LSDA) Call Site Table Encoding";
		callSiteTableEncoding = GccAnalysisUtils.readByte(program, addr);

		createAndCommentData(program, addr, new DwarfEncodingModeDataType(), comment,
			CodeUnit.EOL_COMMENT);

		curSize += BYTE_LEN;
		return addr.add(BYTE_LEN);
	}

	private Address createCallSiteTableLength(Address addr) {
		String comment = "(LSDA) Call Site Table Length";

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);

		int encodedLen = uleb.getLength(buf, AbstractLeb128DataType.MAX_LEB128_ENCODED_VALUE_LEN);

		Object lenObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

		callSiteTableLength = (int) (((Scalar) lenObj).getUnsignedValue());

		createAndCommentData(program, addr, uleb, comment, CodeUnit.EOL_COMMENT);

		curSize += encodedLen;
		return addr.add(encodedLen);

	}

	/**
	 * Create a LSDA Header from the bytes at <code>addr</code>.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * @param addr the start (minimum address) of this LSDA header.
	 * @throws MemoryAccessException if memory for the header couldn't be read.
	 */
	public void create(Address addr) throws MemoryAccessException {

		/* use current program location if 'addr' is null */
		if (addr == null || monitor.isCancelled()) {
			return;
		}

		monitor.setMessage("Creating GCC Exception Table Header");
		Address baseAddr = addr;

		addr = createLPStartEncoding(addr);

		addr = createLPStartPointer(addr);

		addr = createTTypeEncoding(addr);

		addr = createTTypeOffset(addr);

		Address callSiteTableStart = addr;
		addr = createCallSiteTableEncoding(addr);

		addr = createCallSiteTableLength(addr);

		headerSize = addr.subtract(baseAddr);
		callSiteTableHeaderSize = addr.subtract(callSiteTableStart);

		Address extent = addr.add(getCallSiteTableLength() - 1);

		if (ttypeEncoding != OMITTED_ENCODING_TYPE) {
			ttypeAddr = baseAddr.add(ttypeOffset);
			extent = ttypeAddr;
		}

		tableBounds = new AddressRangeImpl(baseAddr, extent);

		String tableLabel = "lsda_exception_table_" + baseAddr;

		try {
			Symbol sym = program.getSymbolTable().getPrimarySymbol(baseAddr);
			if (sym == null) {
				sym =
					program.getSymbolTable().createLabel(baseAddr, tableLabel, SourceType.ANALYSIS);
			}
			else {
				sym.setName(tableLabel, SourceType.ANALYSIS);
			}
		}
		catch (Exception e) {
			// ignored
		}

		SetCommentCmd commentCmd =
			new SetCommentCmd(baseAddr, CodeUnit.PLATE_COMMENT, "(LSDA) Exception Table");
		commentCmd.applyTo(program);

		nextAddress = addr;
	}

	/**
	 * Gets the next address indicating the address after this LSDA header.
	 * @return the next address after this LSDA header or null if this LSDA header hasn't been 
	 * created at any address yet.
	 */
	public Address getNextAddress() {
		return nextAddress;
	}

	/**
	 * Gets the address range containing the LSDA header.
	 * @return the address range of the header
	 */
	public AddressRange getBody() {
		return tableBounds;
	}

	/**
	 * Gets the size of this LSDA header.
	 * @return the header size
	 */
	public long getHeaderSize() {
		return headerSize;
	}

	/**
	 * Gets the indicator of the encoding used for the landing pad start.
	 * @return the LP start encoding
	 */
	public int getLPStartEncoding() {
		return lpStartEncoding;
	}

	/**
	 * Gets the landing pad start address.
	 * @return the LP start address
	 */
	public Address getLPStartAddress() {
		return lpStartAddr;
	}

	/**
	 * Determines if this LSDA has a type table.
	 * @return true if there is a type table
	 */
	public boolean hasTypeTable() {
		return hasTypeTable && ttypeAddr != Address.NO_ADDRESS;
	}

	/**
	 * Gets the encoding used for the type table.
	 * @return the value indicating the type table's encoding
	 */
	public int getTTypeEncoding() {
		return ttypeEncoding;
	}

	/**
	 * The offset from the type offset field to get to the base address of the type table.
	 * @return the type table offset
	 */
	public int getTTypeOffset() {
		return (int) ttypeOffset;
	}

	/**
	 * Gets the base address of the type table. The base address is the last byte (maximum address) 
	 * of the type table. The type table is ordered in reverse.
	 * @return the type table's base address or <code>Address.NO_ADDRESS</code>
	 */
	public Address getTTypeBaseAddress() {
		return ttypeAddr;
	}

	/**
	 * Gets the dwarf encoding used for the call site table.
	 * @return the encoding value
	 */
	public int getCallSiteTableEncoding() {
		return callSiteTableEncoding;
	}

	/**
	 * Gets the length of the call site table.
	 * @return the table length
	 */
	public int getCallSiteTableLength() {
		return callSiteTableLength;
	}

	/**
	 * Get the size of the header in the call site table.
	 * @return the header size
	 */
	public int getCallSiteTableHeaderSize() {
		return (int) callSiteTableHeaderSize;
	}
}
