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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.DwarfEncodingModeDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents an Exception Handler Frame Header.
 * <pre>
 * struct eh_frame_hdr {
 *     unsigned char eh_frame_header_version
 *     unsigned char eh_frame_pointer_encoding
 *     unsigned char eh_frame_description_entry_count
 *     unsigned_char eh_handler_table_encoding
 * }
 * </pre>
 */
public class ExceptionHandlerFrameHeader {
	
	/* Class Members */
	private TaskMonitor monitor;
	private Program prog;
	private StructureDataType ehFrameHdrStruct;
	private int eh_version;
	private int eh_FramePtrEncoding;
	private int eh_FrameDescEntryCntEncoding;
	private int eh_FrameTableEncoding;
	
	/**
	 * Constructor for an ExceptionHandlerFrameHeader.
	 * @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
	 * @param curProg the program containing this eh frame header.
	 */
	public ExceptionHandlerFrameHeader(TaskMonitor monitor, Program curProg) {
		this.monitor = monitor;
		this.prog = curProg;
		ehFrameHdrStruct = new StructureDataType("eh_frame_hdr", 0);

		/* Build the Exception Handler Frame Header Structure */
		ehFrameHdrStruct.add(new ByteDataType(), "eh_frame_hdr_version",
			"Exception Handler Frame Header Version");
		ehFrameHdrStruct.add(new DwarfEncodingModeDataType(), "eh_frame_pointer_encoding",
			"Exception Handler Frame Pointer Encoding");
		ehFrameHdrStruct.add(new DwarfEncodingModeDataType(), "eh_frame_desc_entry_count_encoding",
			"Encoding of # of Exception Handler FDEs");
		ehFrameHdrStruct.add(new DwarfEncodingModeDataType(), "eh_frame_table_encoding",
			"Exception Handler Table Encoding");
	}

	/**
	 * Adds the structure data type for the eh frame header to the program's data type manager.
	 */
	public void addToDataTypeManager() {
		DataTypeManager dtManager = prog.getDataTypeManager();
		
		/* Add the ehFrameHdr Structure to the dataTypeManager */
		dtManager.addDataType(ehFrameHdrStruct, DataTypeConflictHandler.REPLACE_HANDLER );
	}
	
	/**
	 * Method that creates an Exception Handler Frame Header Structure
	 * at the address specified by 'addr'. If addr is 'null', this method returns without creating
	 * the structure.
	 * 
	 * @param addr - Address at which the Exception Handler Frame Header Structure should be created.
	 * @throws AddressOutOfBoundsException if the memory needed for this frame header isn't in the program.
	 * @throws MemoryAccessException if the memory needed for this frame header isn't in the program.
	 */
	public void create(Address addr) throws MemoryAccessException, AddressOutOfBoundsException {
		CreateStructureCmd dataCmd = null;
		
		if (addr == null || monitor.isCancelled()) {
			return;
		}
		
		/* Create a new structure at the start of the .eh_frame_hdr section */
		dataCmd = new CreateStructureCmd( ehFrameHdrStruct, addr );
		dataCmd.applyTo(prog);
		
		/* Set a comment on the newly created structure */
		SetCommentCmd commentCmd = new SetCommentCmd(addr, CodeUnit.PLATE_COMMENT, "Exception Handler Frame Header");
		commentCmd.applyTo(prog);
		
		// Set the class members accordingly
		eh_version = prog.getMemory().getByte(addr) & 0xFF;
		eh_FramePtrEncoding = prog.getMemory().getByte(addr.add(1)) & 0xFF;
		eh_FrameDescEntryCntEncoding = prog.getMemory().getByte(addr.add(2)) & 0xFF;
		eh_FrameTableEncoding = prog.getMemory().getByte(addr.add(3)) & 0xFF;
	}

	/**
	 * Gets the length of the EH Frame Header.
	 * 
	 * @return the length of this frame header.
	 */
	public int getLength() {
		return ehFrameHdrStruct.getLength();
	}

	/**
	 * Gets the version for this program's eh frame.
	 * @return the version indicator.
	 */
	public int getEh_FrameVersion() {
		return eh_version;
	}

	/**
	 * Gets the eh frame description entry count.
	 * @return the description entry count.
	 */
	public int getEh_FrameDescEntryCntEncoding() {
		return eh_FrameDescEntryCntEncoding;
	}

	/**
	 * Gets the eh frame pointer encoding.
	 * @return the pointer encoding.
	 */
	public int getEh_FramePtrEncoding() {
		return eh_FramePtrEncoding;
	}

	/**
	 * Gets the eh handler table encoding.
	 * @return the table encoding.
	 */
	public int getEh_FrameTableEncoding() {
		return eh_FrameTableEncoding;
	}

}
