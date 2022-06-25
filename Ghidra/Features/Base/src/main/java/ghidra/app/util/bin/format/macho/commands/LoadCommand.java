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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a load_command structure
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
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
	 * Marks-up the program with the data structures for this load command
	 * 
	 * @param header the mach header
	 * @param api the flat program api
	 * @param baseAddress the base address to apply the mark-up
	 * @param isBinary true if mach-o was loaded as binary
	 * @param parentModule parent module to create fragments
	 * @param monitor the task monitor
	 * @param log the message logS
	 */
	public abstract void markup(MachHeader header, FlatProgramAPI api, Address baseAddress,
			boolean isBinary, ProgramModule parentModule, TaskMonitor monitor, MessageLog log);

	///////////////////////////////////////////////////////////////////////

	protected final ProgramFragment createFragment(FlatProgramAPI api, Address baseAddress,
			ProgramModule module) throws Exception {
		Address start = baseAddress.getNewAddress(getStartIndex());
		return api.createFragment(module, getCommandName(), start, getCommandSize());
	}

	protected final void updateMonitor(TaskMonitor monitor) {
		monitor.setMessage("Processing " + getCommandName() + "...");
	}
}
