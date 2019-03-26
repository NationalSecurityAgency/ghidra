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
package ghidra.app.plugin.exceptionhandlers.gcc.sections;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.*;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Parses the exception handling structures within an '.eh_frame_hdr' memory section; contains 
 * the frame header record and the FDE table.
 */
public class EhFrameHeaderSection {

	/* Class Constants */
	public static final String EH_FRAME_HEADER_BLOCK_NAME = ".eh_frame_hdr";

	/* Class Members */
	private Program program;

	/**
	 * Constructor for an eh frame header section.
	 * 
	 * @param program the program containing this eh frame header.
	 */
	public EhFrameHeaderSection(Program program) {
		this.program = program;
	}

	/**
	 * Analyzes and annotates the eh frame header.
	 * @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
	 * @return the number of records in the FDE table or 0 if there was no EH frame header to analyze.
	 * @throws MemoryAccessException if memory couldn't be read/written while processing the header.
	 * @throws AddressOutOfBoundsException if one or more expected addresses weren't in the program.
	 * @throws ExceptionHandlerFrameException if the FDE table can't be decoded.
	 */
	public int analyze(TaskMonitor monitor) throws MemoryAccessException,
			AddressOutOfBoundsException, ExceptionHandlerFrameException {

		MemoryBlock memBlock = program.getMemory().getBlock(EH_FRAME_HEADER_BLOCK_NAME);

		if (memBlock != null && !monitor.isCancelled()) {
			return analyzeSection(memBlock, monitor);
		}
		return 0;
	}

	private int analyzeSection(MemoryBlock curMemBlock, TaskMonitor monitor)
			throws MemoryAccessException, AddressOutOfBoundsException,
			ExceptionHandlerFrameException {

		monitor.setMessage("Analyzing .eh_frame_hdr section");

		ProgramLocation loc = new ProgramLocation(program, curMemBlock.getStart());
		Address curAddress = loc.getAddress();

		ExceptionHandlerFrameHeader eh_frame_hdr =
			new ExceptionHandlerFrameHeader(monitor, program);
		eh_frame_hdr.addToDataTypeManager();
		eh_frame_hdr.create(curAddress);

		curAddress = curAddress.add(eh_frame_hdr.getLength());

		// NOTE: The process... method calls that follow are order dependent.
		//       Each one is passed the address of the field it will process and 
		//       returns the next address after that field, which will then be 
		//       used by the next field's process method.

		curAddress = processEncodedFramePointer(curAddress, eh_frame_hdr, curMemBlock);

		DwarfEHDecoder fdeCountDecoder = getFdeCountDecoder(eh_frame_hdr);
		Address fdeCountAddress = curAddress;

		curAddress = processEncodedFdeCount(fdeCountAddress, fdeCountDecoder);

		int fdeTableCnt = getFdeTableCount(fdeCountAddress, curMemBlock, fdeCountDecoder);
		if (fdeTableCnt > 0) {
			createFdeTable(curAddress, eh_frame_hdr, fdeTableCnt, monitor);
		}
		return fdeTableCnt;
	}

	/**
	 * Create the data field for the number of entries in the FDE table 
	 * and add an identifying comment.
	 * 
	 * @param curAddress address of the FDE count field
	 * @param fdeDecoder decoder to use in determining data type for this field
	 * @return the next address after the FDE count field
	 */
	private Address processEncodedFdeCount(Address curAddress, DwarfEHDecoder fdeDecoder) {

		/* Create the Encoded FDE count member */
		DataType encDataType = fdeDecoder.getDataType(program);

		CreateDataCmd dataCmd = new CreateDataCmd(curAddress, encDataType);
		dataCmd.applyTo(program);

		SetCommentCmd commentCmd =
			new SetCommentCmd(curAddress, CodeUnit.EOL_COMMENT, "Encoded FDE count");
		commentCmd.applyTo(program);

		curAddress = curAddress.add(encDataType.getLength());
		return curAddress;
	}

	private DwarfEHDecoder getFdeCountDecoder(ExceptionHandlerFrameHeader eh_frame_hdr) {
		int fdeCntEnc = eh_frame_hdr.getEh_FrameDescEntryCntEncoding();
		DwarfEHDecoder fdeDecoder = DwarfDecoderFactory.getDecoder(fdeCntEnc);
		return fdeDecoder;
	}

	/**
	 * Create the data field for the exception handler frame pointer. Also create the associated 
	 * reference, and add an identifying comment.
	 * 
	 * @param curAddress address of the frame pointer field
	 * @param eh_frame_hdr the frame header with encoding information
	 * @param curMemBlock the memory block containing this header
	 * @return the next address after the frame pointer field
	 * @throws MemoryAccessException if the field's memory can't be read
	 */
	private Address processEncodedFramePointer(Address curAddress,
			ExceptionHandlerFrameHeader eh_frame_hdr, MemoryBlock curMemBlock)
			throws MemoryAccessException {

		/* Create the encoded Exception Handler Frame Pointer */
		DwarfEHDecoder frmPtrDecoder =
			DwarfDecoderFactory.getDecoder(eh_frame_hdr.getEh_FramePtrEncoding());
		Address frmPtrAddr =
			frmPtrDecoder.decodeAddress(new DwarfDecodeContext(program, curAddress, curMemBlock));

		program.getReferenceManager().addMemoryReference(curAddress, frmPtrAddr, RefType.DATA,
			SourceType.ANALYSIS, 0);

		DataType frmPtrDataType = frmPtrDecoder.getDataType(program);

		CreateDataCmd dataCmd = new CreateDataCmd(curAddress, frmPtrDataType);
		dataCmd.applyTo(program);

		SetCommentCmd commentCmd =
			new SetCommentCmd(curAddress, CodeUnit.EOL_COMMENT, "Encoded eh_frame_ptr");
		commentCmd.applyTo(program);

		curAddress = curAddress.add(frmPtrDataType.getLength());
		return curAddress;
	}

	private int getFdeTableCount(Address countAddress, MemoryBlock curMemBlock,
			DwarfEHDecoder fdeDecoder) throws MemoryAccessException {

		DwarfDecodeContext context = new DwarfDecodeContext(program, countAddress, curMemBlock);
		int fdeTableCnt = (int) fdeDecoder.decode(context);
		return fdeTableCnt;
	}

	private void createFdeTable(Address curAddress, ExceptionHandlerFrameHeader eh_frame_hdr,
			int fdeTableCnt, TaskMonitor monitor) throws MemoryAccessException,
			ExceptionHandlerFrameException {

		/* Build the Frame Descriptor Entry Table */
		int fdeTblEnc = eh_frame_hdr.getEh_FrameTableEncoding();
		DwarfEHDecoder fdeTblDecoder = DwarfDecoderFactory.getDecoder(fdeTblEnc);

		FdeTable fde_table = new FdeTable(monitor, program);
		fde_table.create(curAddress, fdeTblDecoder, fdeTableCnt);

		SetCommentCmd commentCmd =
			new SetCommentCmd(curAddress, CodeUnit.PLATE_COMMENT, "Frame Description Entry Table");
		commentCmd.applyTo(program);
	}

}
