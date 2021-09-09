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

import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecodeContext;
import ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Class that builds the Frame Description Entry (FDE) Table for a Common Information Entry (CIE).
 * <p>
 * Call Frame Instructions (taken from gcc-3.2.3-20030829/gcc/dwarf2.h
 * <pre>
    DW_CFA_advance_loc = 0x40,
    DW_CFA_offset = 0x80,
    DW_CFA_restore = 0xc0,
    DW_CFA_nop = 0x00,
    DW_CFA_set_loc = 0x01,
    DW_CFA_advance_loc1 = 0x02,
    DW_CFA_advance_loc2 = 0x03,
    DW_CFA_advance_loc4 = 0x04,
    DW_CFA_offset_extended = 0x05,
    DW_CFA_restore_extended = 0x06,
    DW_CFA_undefined = 0x07,
    DW_CFA_same_value = 0x08,
    DW_CFA_register = 0x09,
    DW_CFA_remember_state = 0x0a,
    DW_CFA_restore_state = 0x0b,
    DW_CFA_def_cfa = 0x0c,
    DW_CFA_def_cfa_register = 0x0d,
    DW_CFA_def_cfa_offset = 0x0e,

    //DWARF 3. //
    DW_CFA_def_cfa_expression = 0x0f,
    DW_CFA_expression = 0x10,
    DW_CFA_offset_extended_sf = 0x11,
    DW_CFA_def_cfa_sf = 0x12,
    DW_CFA_def_cfa_offset_sf = 0x13,
 * </pre>
 *
 */
public class FdeTable {

	/* Class Members */
	TaskMonitor monitor;
	Program prog;
	StructureDataType fdeTableEntry;

	/**
	 * Constructor for an FDE table. 
	 * 
	 * @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
	 * @param curProg the program containing the FDE table.
	 */
	public FdeTable(TaskMonitor monitor, Program curProg) {
		this.monitor = monitor;
		this.prog = curProg;
		this.fdeTableEntry = new StructureDataType("fde_table_entry", 0);
	}

	private void initFdeTableDataType(DwarfEHDecoder decoder) throws ExceptionHandlerFrameException {

		DataType encodedDt = decoder.getDataType(prog);

		if (encodedDt.getLength() <= 0) {
			throw new ExceptionHandlerFrameException(
				"Cannot build FDE structure with Dynamic or Void value type: " +
					encodedDt.getClass().getName());
		}

		if (encodedDt.hasLanguageDependantLength()) {
			// Should avoid using value types whose size fluctuates with Data Organization
			throw new ExceptionHandlerFrameException(
				"Cannot build FDE structure with dynamically-sized value type: " +
					encodedDt.getClass().getName());
		}

		fdeTableEntry.deleteAll();

		fdeTableEntry.add(encodedDt, "initial_loc", "Initial Location");
		fdeTableEntry.add(encodedDt, "data_loc", "Data location");

		DataTypeManager dtManager = prog.getDataTypeManager();
		dtManager.addDataType(fdeTableEntry, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	/**
	 * Creates an FDE Table at the specified Address.
	 * 
	 * @param addr Address at which the FDE Table should be created.
	 * @param decoder the decoder for DWARF encoded exception handling information
	 * @param fdeTableCnt the number of exception handler FDEs.
	 * @throws MemoryAccessException if the needed memory can't be read.
	 * @throws ExceptionHandlerFrameException if the FDE table can't be decoded.
	 */
	public void create(Address addr, DwarfEHDecoder decoder, long fdeTableCnt)
			throws MemoryAccessException, ExceptionHandlerFrameException {
		CreateStructureCmd dataCmd = null;
		long curFdeTableCnt = 0;

		if (addr == null || decoder == null) {
			return;
		}

		initFdeTableDataType(decoder);

		monitor.setMessage("Creating Frame Description Table Entries");
		monitor.setShowProgressValue(true);
		monitor.setIndeterminate(false);
		monitor.initialize(fdeTableCnt);

		/* Create a new FDE structures beginning at startAddress */
		MemoryBlock curMemBlock = prog.getMemory().getBlock(".eh_frame_hdr");
		while( curMemBlock != null &&
				  (addr.compareTo( curMemBlock.getEnd()) < 0) && 
				  (curFdeTableCnt < fdeTableCnt) )
		{
			if (monitor.isCancelled()) {
				return;
			}

			/* Create a new FDE structure */
			dataCmd = new CreateStructureCmd(fdeTableEntry, addr);
			dataCmd.applyTo(prog);

			/*
			 * -- Create references to the 'initial location' and 'data
			 * location' --
			 */
			Data fdeTableData = prog.getListing().getDataAt(addr);
			Structure fdeStruct = (Structure) fdeTableData.getDataType();

			DataTypeComponent locComponent = fdeStruct.getComponent(0);
			Address locComponentAddr = addr.add(locComponent.getOffset());
			DwarfDecodeContext locDecodeContext =
				new DwarfDecodeContext(prog, locComponentAddr, curMemBlock);
			Address locAddr = decoder.decodeAddress(locDecodeContext);

			// this is an indirect reference to code from the table,
			//  so tag reference as an indirect code flow
			// TODO: This should be a CODE flow, leaving as INDIRECTION until refactor
			prog.getReferenceManager().addMemoryReference(locComponentAddr, locAddr,
				RefType.INDIRECTION,
						SourceType.ANALYSIS, 0);

			DataTypeComponent dataComponent = fdeStruct.getComponent(1);
			Address dataComponentAddr = addr.add(dataComponent.getOffset());
			DwarfDecodeContext dataDecodeContext =
				new DwarfDecodeContext(prog, dataComponentAddr, curMemBlock);
			Address dataAddr = decoder.decodeAddress(dataDecodeContext);

			prog.getReferenceManager().addMemoryReference(dataComponentAddr, dataAddr, RefType.DATA,
						SourceType.ANALYSIS, 0);

			/* Increment curAddress by number of bytes in a FDE Table entry */
			curFdeTableCnt++;
			addr = addr.add(fdeTableEntry.getLength());

			monitor.incrementProgress(1);
		}
	}
}
