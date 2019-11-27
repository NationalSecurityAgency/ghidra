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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * A Common Information Entry (CIE) holds information that is shared among many
 * Frame Description Entries (FDEs). There is at least one CIE in every
 * non-empty .debug_frame section.
 * <p>
 * The structures modeled here are described in detail in the C++ ABI.
 */
public class Cie extends GccAnalysisClass {

	/* Class Constants */
	private static final int DWORD_LEN = new DWordDataType().getLength();
	private static final int QWORD_LEN = new QWordDataType().getLength();
	private static final int BYTE_LEN = new ByteDataType().getLength();

	/* Class Members */
	private final boolean isInDebugFrame;

	private boolean endOfFrame = false;
	private byte[] enc_length;
	private int intLength;
	private byte[] enc_extLength;
	private boolean hasExtLength;
	private byte[] enc_cieId;
	private int cieId;
	private byte version;
	private String augmentationString;
	private int segmentSize;
	private int codeAlignFactor;
	private int dataAlignFactor;
	private int returnAddrRegister;
	private int augmentationDataLength;
	private byte[] augmentationData;
	private byte[] initialInstructions;
	private int curSize;

	private Address baseAddress;
	private Address nextAddress;

	private int fdeEncoding = 0x0;
	private int lsdaEncoding = 0x0;

	private int personalityFuncAddrEncoding = 0x0;
	private Address personalityFuncAddr = null;
	private int initialInstructionCount;

	/**
	 * Creates a common information entry object that is not in the debug frame section.
	 * <p>Note: The <code>create(Address)</code> method must be called after constructing a 
	 * <code>Cie</code> to associate it with an address before any of its "process..." methods are called.
	 * 
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the CIE.
	 */
	public Cie(TaskMonitor monitor, Program program) {
		this(monitor, program, false);
	}

	/**
	 * Creates a common information entry object.
	 * <p>Note: The <code>create(Address)</code> method must be called after constructing a 
	 * <code>Cie</code> to associate it with an address before any of its "process..." methods are called.
	 * 
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program containing the CIE.
	 * @param isInDebugFrame true if this CIE is in the debug frame section
	 */
	public Cie(TaskMonitor monitor, Program program, boolean isInDebugFrame) {
		super(monitor, program);
		this.isInDebugFrame = isInDebugFrame;
		enc_length = new byte[4]; // 4-byte unsigned value
		enc_extLength = new byte[8]; // 8-byte unsigned value
		hasExtLength = false;
		enc_cieId = new byte[4]; // 4-byte unsigned value
		curSize = 0;
		super.init(program);
	}

	/**
	 * Determines if this CIE is in the debug frame section.
	 * 
	 * @return true if in the debug frame section.
	 */
	public boolean isInDebugFrame() {
		return isInDebugFrame;
	}

	/**
	 * Creates the CIE Length field at the specified location.
	 * 
	 * @param addr Address at which the CIE Length field should be created.
	 * @return Address immediately following the CIE length field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processCieLength(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE Length field at the specified address and sets an
		 * appropriate comment for the new structure.
		 */
		String comment = "(CIE) Length";
		createAndCommentData(program, addr, dwordDT, comment, CodeUnit.EOL_COMMENT);
		program.getMemory().getBytes(addr, enc_length);
		curSize += DWORD_LEN;

		/*
		 * Calculate the integer values for the length field This is done
		 * because many of the comparisons use int values.
		 */
		intLength = getIntegerLength();

		return addr.add(DWORD_LEN);
	}

	/**
	 * Creates the CIE ID field at the specified Address.
	 * 
	 * @param addr Address at which the CIE ID field should be created.
	 * @return Address immediately following the CIE ID field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processCieId(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE ID field at the specified address and sets an
		 * appropriate comment for the new structure.
		 */
		String comment = "(CIE) ID";
		createAndCommentData(program, addr, dwordDT, comment, CodeUnit.EOL_COMMENT);

		program.getMemory().getBytes(addr, enc_cieId);
		cieId = (int) GccAnalysisUtils.readDWord(program, addr);
		curSize = +DWORD_LEN;

		return addr.add(DWORD_LEN);
	}

	/**
	 * Creates the CIE Version field at the specified location.
	 * 
	 * @param addr Address at which the CIE version field should be created.
	 * @return Address immediately following the CIE version field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processVersion(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE Version field at the specified address and sets an
		 * appropriate comment for the new structure.
		 */
		String comment = "(CIE) Version";
		createAndCommentData(program, addr, new ByteDataType(), comment, CodeUnit.EOL_COMMENT);
		version = GccAnalysisUtils.readByte(program, addr);
		curSize += BYTE_LEN;

		return addr.add(BYTE_LEN);
	}

	/**
	 * Creates the CIE Augmentation String. This is a
	 * case-sensitive, NUL terminated string that identifies the augmentation
	 * to the CIE or to the FDEs associated with this CIE. A zero length string
	 * indicates that no augmentation data is present.
	 * 
	 * @param addr Address at which the Augmentation String should be created.
	 * @return Address immediately following the Augmentation String.
	 * @throws ExceptionHandlerFrameException if the augmentation string couldn't be created.
	 */
	private Address processAugmentationString(Address addr) throws ExceptionHandlerFrameException {

		/*
		 * Create a new CIE Augmentation String field at the specified address
		 * and sets an appropriate comment for the new structure.
		 */
		String comment = "(CIE) Augmentation String";
		createAndCommentData(program, addr, new StringDataType(), comment, CodeUnit.EOL_COMMENT);
		Data dataAt = program.getListing().getDataAt(addr);
		if (dataAt == null) {
			throw new ExceptionHandlerFrameException(
				"Couldn't process augmentation string @ " + addr + ".");
		}
		augmentationString = (String) dataAt.getValue();
		curSize += augmentationString.length() + 1; // Add 1 for the NUL byte
													// '\0'

		return addr.add(augmentationString.length() + 1);
	}

	/**
	 * Creates the CIE Pointer Size field at the specified location
	 * (CIE version 4+).
	 * 
	 * @param addr Address at which the CIE pointer size field should be created.
	 * @return Address immediately following the CIE pointer size field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processPointerSize(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE Pointer Size field at the specified address and sets an
		 * appropriate comment for the new structure.
		 */
		String comment = "(CIE) Pointer Size";
		createAndCommentData(program, addr, new ByteDataType(), comment, CodeUnit.EOL_COMMENT);
		ptrSize = GccAnalysisUtils.readByte(program, addr);
		curSize += BYTE_LEN;

		return addr.add(BYTE_LEN);
	}

	/**
	 * Creates the CIE Segment Size field at the specified location
	 * (CIE version 4+).
	 * 
	 * @param addr Address at which the CIE segment size field should be created.
	 * @return Address immediately following the CIE segment size field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processSegmentSize(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE Version field at the specified address and sets an
		 * appropriate comment for the new structure.
		 */
		String comment = "(CIE) Segment Size";
		createAndCommentData(program, addr, new ByteDataType(), comment, CodeUnit.EOL_COMMENT);
		segmentSize = GccAnalysisUtils.readByte(program, addr);
		curSize += BYTE_LEN;

		return addr.add(BYTE_LEN);
	}

	/**
	 * Creates the CIE Code Alignment Factor Field.
	 * 
	 * @param addr Address at which the Code Alignment Factor field should be created.
	 * @return Address immediately following the Code Alignment Factor field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processCodeAlign(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE code alignment field at the specified address and
		 * sets an appropriate comment for the new structure.
		 */
		String comment = "(CIE) Code Alignment";

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		int encodedLen = uleb.getLength(buf, AbstractLeb128DataType.MAX_LEB128_ENCODED_VALUE_LEN);
		Object augLenObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

		codeAlignFactor = (int) ((Scalar) augLenObj).getUnsignedValue();

		createAndCommentData(program, addr, uleb, comment, CodeUnit.EOL_COMMENT);

		curSize += encodedLen;

		return addr.add(encodedLen);
	}

	/**
	 * Creates the CIE Data Alignment Factor field.
	 * 
	 * @param addr Address at which the Data Alignment Factor field should be created.
	 * @return Address immediately following the Data Alignment Factor field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processDataAlign(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE data alignment field at the specified address and
		 * sets an appropriate comment for the new structure.
		 */
		String comment = "(CIE) Data Alignment";

		SignedLeb128DataType sleb = SignedLeb128DataType.dataType;
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		int encodedLen = sleb.getLength(buf, -1);
		Object alignObj = sleb.getValue(buf, sleb.getDefaultSettings(), encodedLen);

		dataAlignFactor = (int) ((Scalar) alignObj).getSignedValue();

		createAndCommentData(program, addr, sleb, comment, CodeUnit.EOL_COMMENT);

		curSize += encodedLen;

		return addr.add(encodedLen);
	}

	/**
	 * Creates the CIE Return Address Register field.
	 * 
	 * @param addr Address at which the Return Address Register field should be created.
	 * @return Address immediately following the Return Address field.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processReturnAddrRegister(Address addr) throws MemoryAccessException {

		/*
		 * Create a new CIE Return Address Register field at the specified
		 * address and sets an appropriate comment for the new structure.
		 */
		String comment = "(CIE) Return Address Register Column";

		int encodedLen = 0;
		DataType encodedDt = null;
		if (version == (byte) 1) {
			returnAddrRegister = GccAnalysisUtils.readByte(program, addr);
			encodedDt = new ByteDataType();
			// TODO Instead use the following data type once it can correctly determine the register.
			// encodedDt = new DwarfRegisterByteDataType();
			encodedLen = BYTE_LEN;
		}
		else {

			UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;
			encodedDt = uleb;
			// TODO Instead use the following data type once it can correctly determine the register.
			// encodedDt = new DwarfRegisterLeb128DataType();

			MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
			encodedLen = uleb.getLength(buf, AbstractLeb128DataType.MAX_LEB128_ENCODED_VALUE_LEN);
			Object augLenObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

			returnAddrRegister = (int) ((Scalar) augLenObj).getUnsignedValue();

		}

		createAndCommentData(program, addr, encodedDt, comment, CodeUnit.EOL_COMMENT);
		curSize += encodedLen;

		return addr.add(encodedLen);
	}

	/**
	 * Creates the CIE augmentation data length.
	 * 
	 * @param addr Address at which the augmentation data length field should be created.
	 * @return Address immediately following the augmentation data length.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processAugmentationDataLength(Address addr) throws MemoryAccessException {

		/*
		 * Create a new Augmentation Data Length field at the specified address
		 * and sets an appropriate comment for the new structure.
		 */
		String comment = "(CIE) Augmentation Data Length";

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;
		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		int encodedLen = uleb.getLength(buf, AbstractLeb128DataType.MAX_LEB128_ENCODED_VALUE_LEN);
		Object augLenObj = uleb.getValue(buf, uleb.getDefaultSettings(), encodedLen);

		augmentationDataLength = (int) ((Scalar) augLenObj).getUnsignedValue();

		createAndCommentData(program, addr, uleb, comment, CodeUnit.EOL_COMMENT);

		curSize += encodedLen;

		return addr.add(encodedLen);

	}

	/**
	 * Reads the CIE Augmentation Data and holds it in this class. This block of data is
	 * defined by the contents of the Augmentation String and is only present if
	 * the Augmentation string contains the character 'z'. Length of this string
	 * is given by the Augmentation length.
	 * 
	 * @param addr Address at which the Augmentation Data array should be created.
	 * @return Address immediately following the Augmentation Data
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address grabAugmentationData(Address addr) throws MemoryAccessException {

		/*
		 * Copies the Augmentation Data at the specified address into <code>augmentationData</code>
		 * so it can be processed.
		 */
		augmentationData = new byte[augmentationDataLength];
		int numBytesRead = program.getMemory().getBytes(addr, augmentationData);

		curSize += numBytesRead;

		return addr.add(numBytesRead);
	}

	/**
	 * Creates the initial set of Call Frame instructions. The
	 * number of instructions is determined by the remaining space in the CIE
	 * record.
	 * 
	 * @param addr Address at which the initial instructions array should be created.
	 * @return Address immediately following the initial instructions array
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 */
	private Address processInitialInstructions(Address addr) throws MemoryAccessException {
		CreateArrayCmd arrayCmd = null;

		// Create initial instructions array with remaining bytes
		initialInstructionCount = intLength - curSize;
		arrayCmd = new CreateArrayCmd(addr, initialInstructionCount, new ByteDataType(), BYTE_LEN);
		arrayCmd.applyTo(program);
		SetCommentCmd.createComment(program, addr, "(CIE) Initial Instructions",
			CodeUnit.EOL_COMMENT);

		initialInstructions = new byte[initialInstructionCount];
		int numBytesRead = program.getMemory().getBytes(addr, initialInstructions);

		// *** The following commented out code is for debugging purposes. ***
//		DwarfCallFrameOpcodeParser parser =
//			new DwarfCallFrameOpcodeParser(program, addr, numBytesRead);
//		parser.parse();

		curSize += numBytesRead;

		try {
			return addr.add(numBytesRead);
		}
		catch (AddressOutOfBoundsException e) {
			return null; // reached end of block
		}
	}

	/**
	 * Creates a Common Information Entry (CIE) at <code>cieAddress</code>. 
	 * <br>Note: This method must get called before any of the "get..." methods.
	 * 
	 * @param cieAddress the address where the CIE should be created.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read.
	 * @throws ExceptionHandlerFrameException if some of the CIE information couldn't be created.
	 */
	public void create(Address cieAddress)
			throws MemoryAccessException, ExceptionHandlerFrameException {

		if (cieAddress == null || monitor.isCancelled()) {
			return;
		}

		baseAddress = cieAddress;
		monitor.setMessage("Creating Common Information Entries");

		Address currentAddress = cieAddress;

		// See if processing should stop due to the current length field == 0
		if (program.getMemory().getInt(currentAddress) == 0) {
			markEndOfFrame(currentAddress);
			endOfFrame = true;
			return;
		}

		// NOTE: The process... method calls that follow are order dependent.
		//       Each one is passed the address of the field it will process and 
		//       returns the next address after that field, which will then be 
		//       used by the next field's process method.

		// Create the CIE length field
		currentAddress = processCieLength(currentAddress);
		currentAddress = processExtendedLength(currentAddress);

		/* Create the CIE fields & update the current address as you go. */

		currentAddress = processCieId(currentAddress);
		currentAddress = processVersion(currentAddress);
		currentAddress = processAugmentationString(currentAddress);

		if (version >= (byte) 4) {
			currentAddress = processPointerSize(currentAddress);
			currentAddress = processSegmentSize(currentAddress);
		}

		currentAddress = processCodeAlign(currentAddress);
		currentAddress = processDataAlign(currentAddress);
		currentAddress = processReturnAddrRegister(currentAddress);

		if (isInDebugFrame) {
			fdeEncoding = 0x0;
		}
		else {
			currentAddress = processAugmentationInfo(currentAddress);
		}

		/*
		 * Add initial instructions section and possible padding from remaining bytes.
		 */
		if (!hasExtLength) {
			if (curSize < intLength) {
				currentAddress = processInitialInstructions(currentAddress);
			}
		}
		else {
			throw new ExceptionHandlerFrameException("ExtLength is not completely implemented.");
		}

		nextAddress = currentAddress;
	}

	private void markEndOfFrame(Address addr) {
		createAndCommentData(program, addr, dwordDT, "End of Frame", CodeUnit.EOL_COMMENT);
		SetCommentCmd commentCmd = new SetCommentCmd(addr, CodeUnit.PLATE_COMMENT, "END OF FRAME");
		commentCmd.applyTo(program);
	}

	private int getIntegerLength() {
		ByteBuffer bb = ByteBuffer.wrap(enc_length);
		if (program.getMemory().isBigEndian()) {
			bb.order(ByteOrder.BIG_ENDIAN);
		}
		else {
			bb.order(ByteOrder.LITTLE_ENDIAN);
		}
		return bb.getInt();
	}

	private Address processExtendedLength(Address addr) throws MemoryAccessException {
		/*
		 * If length == 0xfffffff, then next 8-bytes indicate the length of the
		 * CIE structure. (Not including the "Length" field itself)
		 */
		if (intLength == 0xffffffff) {
			hasExtLength = true;
			String comment = "(CIE) Extended Length";
			createAndCommentData(program, addr, new QWordDataType(), comment, CodeUnit.EOL_COMMENT);
			program.getMemory().getBytes(addr, enc_extLength);
			addr = addr.add(QWORD_LEN);
			curSize += QWORD_LEN;
		}
		return addr;
	}

	private Address processAugmentationInfo(Address addr) throws MemoryAccessException {

		/*
		 * If the first character is a 'z', Augmentation Data is included.
		 */
		if (augmentationString != null && augmentationString.length() > 0 &&
			augmentationString.charAt(0) == 'z') {

			// Create the Augmentation Data Length and Augmentation Data fields
			addr = processAugmentationDataLength(addr);
			Address augmentationDataAddr = addr;
			addr = grabAugmentationData(addr);

			int augmentationDataIndex = 0;
			for (int idx = 1; idx < augmentationString.length(); idx++) {
				if (augmentationDataIndex >= augmentationData.length) {
					break;
				}
				int augData = augmentationData[augmentationDataIndex] & 0xFF;

				char ch = augmentationString.charAt(idx);
				switch (ch) {
					case 'L':
						processLsdaEncoding(augmentationDataAddr, augmentationDataIndex, augData);
						augmentationDataIndex++;
						break;

					case 'R':
						processFdeEncoding(augmentationDataAddr, augmentationDataIndex, augData);
						augmentationDataIndex++;
						break;

					case 'S':
						Msg.debug(this, "stack frame..");
						break;

					case 'P':

						DwarfEHDecoder personalityDecoder = processPersonalityEncoding(
							augmentationDataAddr, augmentationDataIndex, augData);
						augmentationDataIndex++;

						DwarfDecodeContext personalityDecodeContext =
							processPersonalityFunctionPointer(augmentationDataAddr,
								augmentationDataIndex, personalityDecoder);
						augmentationDataIndex += personalityDecodeContext.getEncodedLength();

						break;
				}

			}
		}
		return addr;
	}

	private void processLsdaEncoding(Address augmentationDataAddr, int augmentationDataIndex,
			int augData) {

		lsdaEncoding = augData;

		String lsdaComment = "(CIE Augmentation Data) LSDA Personality Function Pointer Encoding";

		createAndCommentData(program, augmentationDataAddr.add(augmentationDataIndex),
			new DwarfEncodingModeDataType(), lsdaComment, CodeUnit.EOL_COMMENT);
	}

	private void processFdeEncoding(Address augmentationDataAddr, int augmentationDataIndex,
			int augData) {

		fdeEncoding = augData;

		createAndCommentData(program, augmentationDataAddr.add(augmentationDataIndex),
			new DwarfEncodingModeDataType(), "(CIE Augmentation Data) FDE Encoding",
			CodeUnit.EOL_COMMENT);
	}

	private DwarfEHDecoder processPersonalityEncoding(Address augmentationDataAddr,
			int augmentationDataIndex, int augData) {

		personalityFuncAddrEncoding = augData;

		DwarfEHDecoder personalityDecoder =
			DwarfDecoderFactory.getDecoder(personalityFuncAddrEncoding);
		String prsnltyComment = "(CIE Augmentation Data) Personality Function Pointer Encoding";

		createAndCommentData(program, augmentationDataAddr.add(augmentationDataIndex),
			new DwarfEncodingModeDataType(), prsnltyComment, CodeUnit.EOL_COMMENT);
		return personalityDecoder;
	}

	private DwarfDecodeContext processPersonalityFunctionPointer(Address augmentationDataAddr,
			int augmentationDataIndex, DwarfEHDecoder personalityDecoder)
			throws MemoryAccessException {

		DwarfDecodeContext personalityDecodeContext =
			new DwarfDecodeContext(program, augmentationDataAddr.add(augmentationDataIndex));
		personalityFuncAddr = personalityDecoder.decodeAddress(personalityDecodeContext);

		DataType prnsFuncPtrDt = personalityDecoder.getDataType(program);

		createAndCommentData(program, augmentationDataAddr.add(augmentationDataIndex),
			prnsFuncPtrDt,
			"(CIE Augmentation Data) Personality Function Pointer (" + personalityFuncAddr + ")",
			CodeUnit.EOL_COMMENT);

		program.getReferenceManager().addMemoryReference(
			augmentationDataAddr.add(augmentationDataIndex), personalityFuncAddr, RefType.DATA,
			SourceType.ANALYSIS, 0);
		return personalityDecodeContext;
	}

	/**
	 * Method that returns the address immediately following the Common Information Entry
	 * 
	 * @return Address immediately following the CIE
	 */
	public Address getNextAddress() {
		return nextAddress;
	}

	/**
	 * Gets the augmentation string which indicates optional fields and how to interpret them.
	 * 
	 * @return the augmentation string.
	 */
	public String getAugmentationString() {
		return augmentationString;
	}

	/**
	 * Gets the indicator for the FDE address pointer encoding.
	 * 
	 * @return the FDE address pointer encoding.
	 */
	public int getFDEEncoding() {
		return fdeEncoding;
	}

	/**
	 * Gets the decoder for the FDE that is associated with this CIE.
	 * 
	 * @return the decoder for the FDE
	 */
	public DwarfEHDecoder getFDEDecoder() {
		return DwarfDecoderFactory.getDecoder(getFDEEncoding());
	}

	/**
	 * Gets the indicator for the LSDA pointer encoding.
	 * 
	 * @return the LSDA pointer encoding.
	 */
	public int getLSDAEncoding() {
		return lsdaEncoding;
	}

	/**
	 * Gets the decoder for the LSDA that is associated with this CIE.
	 * 
	 * @return the decoder for the LSDA
	 */
	public DwarfEHDecoder getLSDADecoder() {
		return DwarfDecoderFactory.getDecoder(getLSDAEncoding());
	}

	/**
	 * Gets the address where this CIE is located in the program.
	 * 
	 * @return the address of this CIE.
	 */
	public Address getAddress() {
		return baseAddress;
	}

	/**
	 * Gets the value of the data alignment factor for this CIE record.
	 * 
	 * @return the data alignment factor
	 */
	public int getDataAlignment() {
		return dataAlignFactor;
	}

	/**
	 * Gets the value of the code alignment factor for this CIE record.
	 * 
	 * @return the code alignment factor
	 */
	public int getCodeAlignment() {
		return codeAlignFactor;
	}

	/**
	 * Determines if this CIE encountered a zero length record, which indicates the end of 
	 * the frame.
	 * 
	 * @return true if we are at end of frame due to encountering a zero length record.
	 */
	public boolean isEndOfFrame() {
		return endOfFrame;
	}

	/**
	 * Gets the segment size for this CIE record.
	 * 
	 * @return the segment size
	 */
	public int getSegmentSize() {
		return segmentSize;
	}

	/**
	 * Gets the return address register column for this CIE record.
	 * 
	 * @return the return address register column
	 */
	public int getReturnAddressRegisterColumn() {
		return returnAddrRegister;
	}

	/**
	 * Gets the ID for this CIE record.
	 * 
	 * @return the CIE identifier
	 */
	public int getCieId() {
		return cieId;
	}

}
