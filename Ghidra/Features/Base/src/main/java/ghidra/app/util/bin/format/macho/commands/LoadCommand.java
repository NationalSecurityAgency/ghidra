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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.cmd.formats.MachoBinaryAnalysisCommand;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a load_command structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h">EXTERNAL_HEADERS/mach-o/loader.h</a> 
 */
public abstract class LoadCommand implements StructConverter {
	private long startIndex;
	private int cmd;
	private int cmdsize;

	/**
	 * Creates a new {@link LoadCommand}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the load command
	 * @throws IOException if there was an IO-related error
	 */
	public LoadCommand(BinaryReader reader) throws IOException {
		startIndex = reader.getPointerIndex();
		cmd = reader.readNextInt();
		cmdsize = reader.readNextInt();
	}

	/**
	 * Returns the binary start index of this load command
	 * 
	 * @return the binary start index of this load command
	 */
	public long getStartIndex() {
		return startIndex;
	}

	/**
	 * Gets the type of this load command
	 * 
	 * @return The type of this load command
	 */
	public int getCommandType() {
		return cmd;
	}

	/**
	 * Gets the size of this load command in bytes
	 * 
	 * @return The size of this load command in bytes
	 */
	public int getCommandSize() {
		return cmdsize;
	}

	/**
	 * Gets the name of this load command
	 * 
	 * @return The name of this load command
	 */
	public abstract String getCommandName();

	/**
	 * Gets the file offset of this load command's "linker data".  Not all load commands with data
	 * will have linker data.  Linker data typically resides in the __LINKEDIT segment.
	 * 
	 * @return The file offset of this load command's "linker data", or 0 if it has no linker data
	 */
	public int getLinkerDataOffset() {
		return 0;
	}

	/**
	 * Gets the file size of this load command's "linker data". Not all load commands with data
	 * will have linker data.  Linker data typically resides in the __LINKEDIT segment.
	 * 
	 * @return The file size of this load command's "linker data", or 0 if it has no linker data
	 */
	public int getLinkerDataSize() {
		return 0;
	}

	/**
	 * Gets the {@link Address} of this load command's "data"
	 * 
	 * @param header The Mach-O header
	 * @param space The {@link AddressSpace}
	 * @return The {@link Address} of this load command's "data", or null if it has no data
	 */
	public Address getDataAddress(MachHeader header, AddressSpace space) {
		return null;
	}

	/**
	 * Marks up this {@link LoadCommand} data with data structures and comments.  Assumes the
	 * program was imported as a Mach-O.
	 * 
	 * @param program The {@link Program} to mark up
	 * @param header The Mach-O header
	 * @param addr The {@link Address} of the start of load command data (could be null if no data)
	 * @param source A name that represents where the header came from (could be null)
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, MachHeader header, Address addr, String source,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		// Default is no markup
		return;
	}

	/**
	 * Gets the {@link SegmentCommand segment} that contains the give file offset
	 * 
	 * @param header The Mach-O header
	 * @param fileOffset The file offset
	 * @return The {@link SegmentCommand segment} that contains the give file offset, or null if
	 *   one was not found
	 */
	protected SegmentCommand getContainingSegment(MachHeader header, long fileOffset) {
		for (SegmentCommand segment : header.getAllSegments()) {
			if (fileOffset >= segment.getFileOffset() &&
				fileOffset < segment.getFileOffset() + segment.getFileSize()) {
				return segment;
			}
		}
		return null;
	}

	//-------------------Legacy code to support Raw Binary markup----------------------------------
	/**
	 * Marks-up this {@link LoadCommand} with data structures and comments.  Assumes the program
	 * was imported as a Raw Binary.
	 * 
	 * @param header The Mach-O header
	 * @param api A {@link FlatProgramAPI}
	 * @param baseAddress The base address of the program
	 * @param parentModule The parent {@link ProgramModule module} to create fragments
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @see MachoBinaryAnalysisCommand
	 */
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			createFragment(api, baseAddress, parentModule);
			Address addr = baseAddress.getNewAddress(getStartIndex());
			api.createData(addr, toDataType());
			createPlateComment(api, addr);
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}

	protected final ProgramFragment createFragment(FlatProgramAPI api, Address baseAddress,
			ProgramModule module) throws Exception {
		Address start = baseAddress.getNewAddress(getStartIndex());
		return api.createFragment(module, LoadCommandTypes.getLoadCommandName(getCommandType()),
			start, getCommandSize());
	}

	protected final void createPlateComment(FlatProgramAPI api, Address addr) {
		api.setPlateComment(addr, LoadCommandTypes.getLoadCommandName(getCommandType()));
	}

	protected final void updateMonitor(TaskMonitor monitor) {
		monitor.setMessage("Processing " + getCommandName() + "...");
	}
}
