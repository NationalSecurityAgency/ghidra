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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.UnsignedLeb128DataType;
import ghidra.app.plugin.exceptionhandlers.gcc.sections.CieSource;
import ghidra.app.plugin.exceptionhandlers.gcc.sections.DebugFrameSection;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A Frame Description Entry (FDE) describes the 
 * stack call frame, in particular, how to restore
 * registers.
 * <p>
 * Taken from binutils-2.14.90.0.4/bfd/elf-bfd.h
 * <pre>
 * struct eh_cie_fde { 
 * 		unsigned int offset; 
 * 		unsigned int size; 
 * 		asection *sec;
 * 		unsigned int new_offset; 
 * 		unsigned char fde_encoding; 
 * 		unsigned char *lsda_encoding; 
 * 		unsigned char lsda_offset; 
 * 		unsigned char cie : 1; 
 * 		unsigned char removed : 1; 
 * 		unsigned char make_relative : 1; 
 * 		unsigned char make_lsda_relative : 1; 
 * 		unsigned char per_encoding_relative : 1; 
 * };
 * </pre>
 * <pre>
 * ACTUAL: struct eh_cie_fde { 
 * 		dword fde.length 
 * 		dword fde.ciePointer (Offset to this FDEs CIE) 
 * 		dword fde.pcBegin 
 * 		dword fde.pcRange 
 * 		dword fde.augmentationLength 
 * 		dword fde.augmentationData 
 * 		dword Call Frame Instructions dword 
 * 		!!! NO IDEA !!! 
 * }
 * </pre>
 */
public class FrameDescriptionEntry extends GccAnalysisClass {

	/* Class Constants */
	private static final int DWORD_LEN = DWordDataType.dataType.getLength();
	private static final int QWORD_LEN = QWordDataType.dataType.getLength();
	private static final int BYTE_LEN = ByteDataType.dataType.getLength();

	/* Class Members */
	private byte[] augmentationData;
	private byte[] augmentationDataEx;
	private byte[] callFrameInstructions;
	private boolean hasExtLength;
	private boolean endOfFrame = false;
	private int intLength;
	private int intPtr;
	private int intAugmentationDataLength;
	private int intAugmentationDataExLength = 0;
	private int intPcRange;
	private int curSize;

	private CieSource cieSource;

	private Cie cie;

	private Address baseAddress;

	private String cieAugmentationString;
	private Address nextAddress;

	private Address pcBeginAddr = Address.NO_ADDRESS;
	private Address pcEndAddr = Address.NO_ADDRESS;

	private Address augmentationDataAddr = Address.NO_ADDRESS;
	private Address augmentationDataExAddr = Address.NO_ADDRESS;

	/**
	 * Constructor for a frame descriptor entry.
	 * <br>Note: The <code>create(Address)</code> method must be called after constructing a 
	 * <code>FrameDescriptionEntry</code> to associate it with an address before any of its 
	 * "get..." methods are called.
	 * 
	 * @param monitor a status monitor for tracking progress and allowing cancelling when creating
	 * an FDE.
	 * @param program the program where this will create an FDE.
	 * @param cieSource the call frame information entry for this FDE.
	 */
	public FrameDescriptionEntry(TaskMonitor monitor, Program program, CieSource cieSource) {
		super(monitor, program);

		this.hasExtLength = false;
		this.intAugmentationDataLength = 0; // new byte[4];

		this.cieSource = cieSource;

		this.curSize = 0;
		this.intPtr = 0;
		this.intPcRange = 0;
		super.init(program);
	}

	private int getPointerDecodeSize(Program theProgram) {
		AddressSpace defaultAddressSpace = theProgram.getAddressFactory().getDefaultAddressSpace();
		Address maxAddress = defaultAddressSpace.getMaxAddress();
		int pointerSize = maxAddress.getPointerSize();
		switch (pointerSize) {
			case 3:
				return 4; // 3 uses 4 bytes

			case 5:
			case 6:
			case 7:
				return 8; // 5 thru 7 use 8 bytes

			default:
				return pointerSize;
		}
	}

	private DataType getAddressSizeDataType() {
		int pointerDecodeSize = getPointerDecodeSize(program);
		switch (pointerDecodeSize) {
			case 2:
				return new WordDataType();
			case 4:
				return new DWordDataType();
			case 8:
				return new QWordDataType();
			default:
				throw new IllegalArgumentException(
					"Unhandled pointer size -- " + pointerDecodeSize + " bytes");
		}
	}

	/**
	 * Creates the FDE Length field at the specified address.
	 * 
	 * @param addr Address at which the FDE length field should be created.
	 * @return Address immediately following the FDE Length field.
	 * @throws MemoryAccessException if the required memory can't be read
	 */
	private Address createFdeLength(Address addr) throws MemoryAccessException {

		/* 
		 * Create a new FDE Length field at the specified address 
		 * and sets an appropriate comment for the new structure.
		 */
		String comment = "(FDE) Length";
		createAndCommentData(program, addr, dwordDT, comment, CodeUnit.EOL_COMMENT);
		intLength = program.getMemory().getInt(addr);

		return addr.add(DWORD_LEN);
	}

	/**
	 * Creates the pointer to this FDE's associated CIE
	 *
	 * @param addr Address at which the CIE Pointer should be created.
	 * @return Address immediately following the CIE Pointer field.
	 * @throws MemoryAccessException if the required memory can't be read
	 * @throws ExceptionHandlerFrameException if there is an error creating the information.
	 */
	private Address createCiePointer(Address addr)
			throws MemoryAccessException, ExceptionHandlerFrameException {
		/*
		 * Create a new CIE Pointer field at the specified address and sets an
		 * appropriate comment for the new structure.
		 */
		String comment = "(FDE) CIE Reference Pointer ";

		DataType locType = new DWordDataType();
		int locTypeSize = locType.getLength();

		createAndCommentData(program, addr, locType, comment, CodeUnit.EOL_COMMENT);

		intPtr = (int) GccAnalysisUtils.readDWord(program, addr);

		Address cieAddr = Address.NO_ADDRESS;

		if (isInDebugFrame(addr)) {

			if (intPtr == -1) {
				throw new ExceptionHandlerFrameException(
					"Invalid CIE Reference Pointer (0x" + Integer.toHexString(intPtr) + ")");
			}
			cieAddr = addr.getNewAddress(intPtr); // absolute ref

		}
		else {
			if (intPtr == 0) {
				throw new ExceptionHandlerFrameException(
					"Invalid CIE Reference Pointer (0x" + Integer.toHexString(intPtr) + ")");
			}
			cieAddr = addr.subtract(intPtr); // relative ref
		}

		cie = cieSource.getCie(cieAddr);

		curSize += locTypeSize;

		program.getReferenceManager().addMemoryReference(addr, cieAddr, RefType.DATA,
			SourceType.ANALYSIS, 0);

		return addr.add(locTypeSize);
	}

	private boolean isInDebugFrame(Address addr) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(addr);
		return DebugFrameSection.DEBUG_FRAME_BLOCK_NAME.equals(block.getName());
	}

	/**
	 * Creates the PcBegin field at the specified Address.
	 * 
	 * @param addr Address at which the PcBegin field should be created.
	 * @param region the region descriptor for this FDE
	 * @return Address immediately following the PcBegin field.
	 * @throws ExceptionHandlerFrameException if there is an error creating the information.
	 */
	private Address createPcBegin(Address addr, RegionDescriptor region)
			throws MemoryAccessException, ExceptionHandlerFrameException {

		/* 
		 * If the bytes at the current address are undefined, 
		 * then create the address pointer
		 */
		String comment = "(FDE) PcBegin";

		DwarfDecodeContext ctx =
			new DwarfDecodeContext(program, addr, region.getEHMemoryBlock().getStart());

		pcBeginAddr = cie.getFDEDecoder().decodeAddress(ctx);
		int encodedLen = ctx.getEncodedLength();

		DataType encodedDt = cie.getFDEDecoder().getDataType(program);

		createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);
		if (pcBeginAddr.getOffset() != 0x0) {
			program.getReferenceManager().addMemoryReference(addr, pcBeginAddr, RefType.DATA,
				SourceType.ANALYSIS, 0);
		}

		curSize += encodedLen;
		return addr.add(encodedLen);
	}

	/**
	 * Creates the PcRange field at the specified Address.
	 * 
	 * @param addr Address at which the PcRange field should be created.
	 * @return Address immediately following the PcRange field
	 * or null if next address would be out of bounds.
	 * @throws ExceptionHandlerFrameException if there is an error creating the information.
	 * @throws MemoryAccessException if the required memory can't be read
	 */
	private Address createPcRange(Address addr)
			throws ExceptionHandlerFrameException, MemoryAccessException {

		/* 
		 * Create a new pcRange field at the specified address 
		 * and sets an appropriate comment for the new structure.
		 */
		String comment = "(FDE) PcRange";

		intPcRange = (int) GccAnalysisUtils.readDWord(program, addr);
		if (intPcRange < 0) {
			return null;
		}

		if (intPcRange == 0) {
			intPcRange = 1;
		}
		pcEndAddr = pcBeginAddr.add(intPcRange - 1);

		DataType dataType = getAddressSizeDataType();
		if (dataType.getLength() == 8) {
			// While this is 64-bit system, this length may be encoded as a 32-bit value, 
			// arguing a length needn't use all 8 bytes. If it *is* encoded in 8 bytes, the 
			// top 32-bits will be zero; if it is *not* encoded in 8 and instead 4, the top 32-bits
			// will be non-zero as they're part of the call frame instructions that follow.

			// this dimension can be encoded in less than 8 bytes.
			// ReadElf reads *a byte* for this value
			int next = (int) GccAnalysisUtils.readDWord(program, addr.add(4));
			if (next != 0) {
				dataType = DWordDataType.dataType;
			}
		}

		int dtLength = dataType.getLength();
		createAndCommentData(program, addr, dataType, comment, CodeUnit.EOL_COMMENT);

		curSize += dtLength;

		try {
			Address nextAddr = addr.add(dtLength);
			return nextAddr;
		}
		catch (AddressOutOfBoundsException e) {
			// At the end of the block so return null.
			return null;
		}
	}

	/**
	 * Creates the Augmentation Data Length field at the specified Address.
	 * 
	 * @param addr Address at which the Augmentation Data length should be created.
	 * @return Address immediately following the Augmentation Data length field.
	 * @throws MemoryAccessException if the required memory can't be read
	 */
	private Address createAugmentationDataLength(Address addr) throws MemoryAccessException {

		/* 
		 * Create a new Augmentation Data Length field at the specified address 
		 * and sets an appropriate comment for the new structure.
		 */
		String comment = "(FDE) Augmentation Data Length";

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		int encodedLen = uleb.getLength(buf, -1);
		Object augLenObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

		intAugmentationDataLength = (int) ((Scalar) augLenObj).getUnsignedValue();

		createAndCommentData(program, addr, uleb, comment, CodeUnit.EOL_COMMENT);

		curSize += encodedLen;

		return addr.add(encodedLen);
	}

	/**
	 * Creates the Augmentation Data at the specified Address.
	 * 
	 * @param addr Address at which the Augmentation Data should be created.
	 * @return Address immediately following the Augmentation Data field.
	 * @throws MemoryAccessException if the required memory can't be read
	 */
	private Address createAugmentationData(Address addr) throws MemoryAccessException {
		/* 
		 * Create a new Augmentation Data field at the specified address 
		 * and sets an appropriate comment for the new structure.
		 */
		SetCommentCmd.createComment(program, addr, "(FDE) Augmentation Data", CodeUnit.EOL_COMMENT);

		this.augmentationData = new byte[intAugmentationDataLength];
		program.getMemory().getBytes(addr, augmentationData);
		curSize += intAugmentationDataLength;

		return addr.add(intAugmentationDataLength);
	}

	/**
	 * Creates the Call Frame Instructions at the specified Address.
	 * 
	 * @param addr Address at which the Call Frame Instructions should be created.
	 * @return Address immediately following the Call Frame Instructions.
	 * @throws MemoryAccessException if the required memory can't be read
	 */
	private Address createCallFrameInstructions(Address addr) throws MemoryAccessException {
		CreateArrayCmd arrayCmd = null;

		// Create initial instructions array with remaining bytes.
		int instructionLength = intLength - curSize;
		ArrayDataType adt = new ArrayDataType(ByteDataType.dataType, instructionLength, BYTE_LEN);
		try {
			program.getListing().createData(addr, adt, adt.getLength());
		}
		catch (CodeUnitInsertionException e) {
			CreateDataCmd dataCmd = new CreateDataCmd(addr, adt);
			dataCmd.applyTo(program);
		}

		SetCommentCmd.createComment(program, addr, "(FDE) Call Frame Instructions",
			CodeUnit.EOL_COMMENT);

		callFrameInstructions = new byte[instructionLength];
		program.getMemory().getBytes(addr, callFrameInstructions);

		// *** The following commented out code is for debugging purposes. ***
//		DwarfCallFrameOpcodeParser parser =
//			new DwarfCallFrameOpcodeParser(program, addr, instructionLength);
//		parser.parse();

		curSize += instructionLength;

		try {
			return addr.add(instructionLength);
		}
		catch (AddressOutOfBoundsException aoobe) {
			// if the instructions end *exactly* on the boundary, we'll end up
			// here..
			return addr.add(instructionLength - 1);
		}
	}

	/**
	 * Creates a Frame Description Entry (FDE) at the address
	 * specified.
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * 
	 * @param fdeBaseAddress Address where the FDE should be created.
	 * @return a region descriptor which holds information about this FDE. Otherwise, null.
	 * @throws MemoryAccessException if memory for the FDE or its associated data can't be accessed
	 * @throws ExceptionHandlerFrameException if there is an error creating the FDE information.
	 */
	public RegionDescriptor create(Address fdeBaseAddress)
			throws MemoryAccessException, ExceptionHandlerFrameException {

		if (fdeBaseAddress == null || monitor.isCancelled()) {
			return null;
		}

		Address addr = fdeBaseAddress;
		baseAddress = fdeBaseAddress;
		MemoryBlock ehblock = program.getMemory().getBlock(addr);
		RegionDescriptor region = new RegionDescriptor(ehblock);

		// See if processing should stop due to the current length field == 0
		if (program.getMemory().getInt(addr) == 0) {
			markEndOfFrame(addr);
			endOfFrame = true;
			return null;
		}

		// Begin creating the fields that compose the FDE.
		addr = createFdeLength(addr);
		addr = createExtendedLength(addr);
		addr = createCiePointer(addr);
		addr = createPcBegin(addr, region);
		addr = createPcRange(addr); // This can return null.

		AddressRange addrRange = new AddressRangeImpl(pcBeginAddr, pcEndAddr);

		region.setIPRange(addrRange);

		try {
			/* Create a function at the pcBegin Addr address */
			CreateFunctionCmd createFuncCmd = new CreateFunctionCmd(pcBeginAddr);
			createFuncCmd.applyTo(program);
		}
		catch (AddressOutOfBoundsException e) {
			throw new ExceptionHandlerFrameException(
				e.getMessage() + ": " + pcBeginAddr.toString() + " + " + intPcRange);
		}

		// If some FDE data remains, then it is the augmentation fields or call frame instructions.
		if (curSize < intLength) {

			// Get the Augmentation String from the CIE
			cieAugmentationString = cie.getAugmentationString();

			addr = createAugmentationFields(addr); // If addr is originally null, it remains null.

			/*
			 * Add call frame instructions and possible padding
			 */
			if (!hasExtLength) {
				if (addr != null && curSize < intLength) {
					// Create the call frame instructions w/ the remaining bytes.
					addr = createCallFrameInstructions(addr);
				}
			}
			else {
				throw new ExceptionHandlerFrameException(
					"ExtLength is not completely implemented.");
			}
		}

		createFdeLabel(fdeBaseAddress);

		region.setFrameDescriptorEntry(this);

		createAugmentationInfo(ehblock, region);

		nextAddress = addr; // This could be null.
		return region;
	}

	private void markEndOfFrame(Address addr) {
		createAndCommentData(program, addr, dwordDT, "End of Frame", CodeUnit.EOL_COMMENT);
		SetCommentCmd commentCmd = new SetCommentCmd(addr, CodeUnit.PLATE_COMMENT, "END OF FRAME");
		commentCmd.applyTo(program);
	}

	private Address createExtendedLength(Address addr) {
		/*
		 * If length == 0xfffffff, then next 8-bytes indicate the length of the CIE
		 * structure. (Not including the "Length" field itself)
		 * TODO - figure out if we need to set the length for this.
		 */
		if (intLength == -1) {
			hasExtLength = true;
			String comment = "(FDE) Extended Length";
			createAndCommentData(program, addr, new QWordDataType(), comment, CodeUnit.EOL_COMMENT);
			// prog.getMemory().getBytes(addr, extLength);
			addr = addr.add(QWORD_LEN);
			curSize += QWORD_LEN;
		}
		return addr;
	}

	private Address createAugmentationFields(Address addr) throws MemoryAccessException {
		augmentationDataAddr = null;

		/*
		 * If the first character is a 'z', Augmentation Data is included.
		 */
		if (addr != null && cieAugmentationString != null && cieAugmentationString.length() > 0 &&
			cieAugmentationString.charAt(0) == 'z') {

			// Create the Augmentation Data Length & Augmentation Data fields
			addr = createAugmentationDataLength(addr);
			augmentationDataAddr = addr;
			addr = createAugmentationData(addr);

		}
		return addr;
	}

	private void createFdeLabel(Address fdeBase) {
		try {
			String fdeName = "fde_" + fdeBase.toString();
			Symbol fdeSym = program.getSymbolTable().getPrimarySymbol(fdeBase);
			if (fdeSym == null) {
				fdeSym =
					program.getSymbolTable().createLabel(fdeBase, fdeName, SourceType.ANALYSIS);
			}
			else {
				fdeSym.setName(fdeName, SourceType.ANALYSIS);
			}
		}
		catch (Exception e) {
			Msg.info(this, "Unable to label FDE -- " + e.getMessage());
			/* ignored */
		}
	}

	private void createAugmentationInfo(MemoryBlock ehblock, RegionDescriptor region)
			throws MemoryAccessException {

		if (augmentationDataAddr != null && intAugmentationDataLength != 0) {

			if (cieAugmentationString.indexOf('L') > 1) {
				createLsda(ehblock, region);
			}
			else {

				DwarfEHDecoder decoder = cie.getLSDADecoder();

				DwarfDecodeContext ctx = new DwarfDecodeContext(program, augmentationDataAddr,
					region.getEHMemoryBlock().getStart());

				Address potentialAugmentationDataExAddr = decoder.decodeAddress(ctx);

				if (program.getMemory().contains(potentialAugmentationDataExAddr)) {
					augmentationDataExAddr = potentialAugmentationDataExAddr;

					createData(program, augmentationDataAddr, DWordDataType.dataType);

					program.getReferenceManager().addMemoryReference(augmentationDataAddr,
						augmentationDataExAddr, RefType.DATA, SourceType.ANALYSIS, 0);

					try {

						String label = "eh_augmentation_" + pcBeginAddr + ".." + pcEndAddr + "_" +
							augmentationDataExAddr;

						program.getSymbolTable().createLabel(augmentationDataExAddr, label,
							SourceType.ANALYSIS);
					}
					catch (InvalidInputException e) {
						// ignored
					}
				}
				else {
					CreateArrayCmd arrayCmd = new CreateArrayCmd(augmentationDataAddr,
						intAugmentationDataLength, new ByteDataType(), BYTE_LEN);
					arrayCmd.applyTo(program);
				}
			}

		}
	}

	private void createLsda(MemoryBlock ehblock, RegionDescriptor region)
			throws MemoryAccessException {

		DwarfDecodeContext lsdaDecodeContext =
			new DwarfDecodeContext(program, augmentationDataAddr, ehblock);

		DwarfEHDecoder lsdaDecoder = DwarfDecoderFactory.getDecoder(cie.getLSDAEncoding());
		Address lsdaAddr = lsdaDecoder.decodeAddress(lsdaDecodeContext);

		region.setLSDAAddress(lsdaAddr);

		String lsdaComment = "(FDE Augmentation Data) LSDA Data Pointer";
		createAndCommentData(program, augmentationDataAddr, lsdaDecoder.getDataType(program),
			lsdaComment, CodeUnit.EOL_COMMENT);

		if (augmentationDataAddr.equals(lsdaAddr)) {
			// decoded a reference that returned here -- a null reference
			return;
		}

		program.getReferenceManager().addMemoryReference(augmentationDataAddr, lsdaAddr,
			RefType.DATA, SourceType.ANALYSIS, 0);

		if (!program.getMemory().getAllInitializedAddressSet().contains(lsdaAddr)) {

			String errorMessage = "Can't create LSDA data @ " + lsdaAddr +
				". The address is not in the program's initialized memory!  CIE @ " +
				cie.getAddress() + " FDE @ " + baseAddress;

			// Log error.
			Msg.error(this, errorMessage);

			// Add error bookmark.
			BookmarkManager bookmarkManager = program.getBookmarkManager();
			bookmarkManager.setBookmark(augmentationDataAddr, BookmarkType.ERROR,
				"Exception Handling Data", errorMessage);

			return;
		}

		try {
			LSDATable table = new LSDATable(monitor, program);
			table.create(lsdaAddr, region);
		}
		catch (Exception e) {
			Msg.error(this, "Error creating LSDA @ " + lsdaAddr + "  " + e.getMessage(), e);
		}
	}

	/**
	 * Gets the next address in memory after this FDE record.
	 * 
	 * @return the next address after this FDE or null if at the end of the section
	 */
	public Address getNextAddress() {
		return nextAddress;
	}

	/**
	 * Determines if this FDE encountered a zero length record, which indicates the end of 
	 * the frame.
	 * 
	 * @return true if we are at end of frame due to encountering a zero length record.
	 */
	public boolean isEndOfFrame() {
		return endOfFrame;
	}

	/**
	 * Get the address range that contains the program instructions.
	 * 
	 * @return the address range
	 */
	public AddressRange getProtectionRange() {
		return new AddressRangeImpl(pcBeginAddr, pcEndAddr);
	}

	/**
	 * Get the address of the augmentation data in this FDE record.
	 * 
	 * @return the augmentation data field's address
	 */
	public Address getAugmentationDataAddress() {
		return augmentationDataAddr;
	}

	/**
	 * Gets the bytes which specify the FDE field that refers to the augmentation data.
	 * 
	 * @return the FDE record's augmentation data.
	 */
	public byte[] getAugmentationData() {
		return augmentationData;
	}

	/**
	 * Gets the start address for the call frame augmentation data.
	 * 
	 * @return the address of the call frame augmentation data
	 */
	public Address getAugmentationExDataAddress() {
		return augmentationDataExAddr;
	}

	/**
	 * Sets the value this region descriptor maintains to indicate the length of the 
	 * augmentation data.
	 * 
	 * @param len number of bytes that compose the augmentation data
	 * @return the length of the augmentation data or -1 if it has already been set.
	 */
	public int setAugmentationDataExLength(int len) {
		if (intAugmentationDataExLength > 0) {
			return -1;
		}
		intAugmentationDataExLength = len;

		try {
			updateAugmentationDataEx();
		}
		catch (MemoryAccessException mae) {
			// ignored
		}

		return len;
	}

	private void updateAugmentationDataEx() throws MemoryAccessException {
		augmentationDataEx = new byte[intAugmentationDataExLength];

		program.getMemory().getBytes(getAugmentationExDataAddress(), augmentationDataEx);
	}

	/**
	 * Gets the call frame augmentation data that indicates how registers are saved and restored.
	 * 
	 * @return the augmentation data
	 */
	public byte[] getAugmentationExData() {
		if (augmentationDataEx == null) {
			return new byte[0];
		}
		return augmentationDataEx;
	}

}
