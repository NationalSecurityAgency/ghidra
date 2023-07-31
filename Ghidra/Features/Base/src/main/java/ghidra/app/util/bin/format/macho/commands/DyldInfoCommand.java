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
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_info_command structure
 */
public class DyldInfoCommand extends LoadCommand {
	private int rebaseOff;
	private int rebaseSize;
	private int bindOff;
	private int bindSize;
	private int weakBindOff;
	private int weakBindSize;
	private int lazyBindOff;
	private int lazyBindSize;
	private int exportOff;
	private int exportSize;
	
	private ExportTrie exportTrie;

	/**
	 * Creates and parses a new {@link DyldInfoCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @param header The {@link MachHeader header} associated with this load command
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	DyldInfoCommand(BinaryReader loadCommandReader, BinaryReader dataReader, MachHeader header)
			throws IOException {
		super(loadCommandReader);

		rebaseOff = loadCommandReader.readNextInt();
		rebaseSize = loadCommandReader.readNextInt();
		bindOff = loadCommandReader.readNextInt();
		bindSize = loadCommandReader.readNextInt();
		weakBindOff = loadCommandReader.readNextInt();
		weakBindSize = loadCommandReader.readNextInt();
		lazyBindOff = loadCommandReader.readNextInt();
		lazyBindSize = loadCommandReader.readNextInt();
		exportOff = loadCommandReader.readNextInt();
		exportSize = loadCommandReader.readNextInt();
		
		if (exportOff > 0 && exportSize > 0) {
			dataReader.setPointerIndex(header.getStartIndex() + exportOff);
			exportTrie = new ExportTrie(dataReader);
		}
		else {
			exportTrie = new ExportTrie();
		}
	}

	/**
	 * {@return The rebase info offset}
	 */
	public int getRebaseOffset() {
		return rebaseOff;
	}

	/**
	 * {@return The rebase info size}
	 */
	public int getRebaseSize() {
		return rebaseSize;
	}

	/**
	 * {@return The bind info offset}
	 */
	public int getBindOffset() {
		return bindOff;
	}

	/**
	 * {@return The bind info size}
	 */
	public int getBindSize() {
		return bindSize;
	}

	/**
	 * {@return The weak bind info offset}
	 */
	public int getWeakBindOffset() {
		return weakBindOff;
	}

	/**
	 * {@return The weak bind info size}
	 */
	public int getWeakBindSize() {
		return weakBindSize;
	}

	/**
	 * {@return The lazy bind info offset}
	 */
	public int getLazyBindOffset() {
		return lazyBindOff;
	}

	/**
	 * {@return The lazy bind info size}
	 */
	public int getLazyBindSize() {
		return lazyBindSize;
	}

	/**
	 * {@return The export info offset}
	 */
	public int getExportOffset() {
		return exportOff;
	}

	/**
	 * {@return The export info size}
	 */
	public int getExportSize() {
		return exportSize;
	}
	
	/**
	 * {@return The export trie}
	 */
	public ExportTrie getExportTrie() {
		return exportTrie;
	}

	@Override
	public String getCommandName() {
		return "dyld_info_command";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "rebase_off", "file offset to rebase info");
		struct.add(DWORD, "rebase_size", "size of rebase info");
		struct.add(DWORD, "bind_off", "file offset to binding info");
		struct.add(DWORD, "bind_size", "size of binding info");
		struct.add(DWORD, "weak_bind_off", "file offset to weak binding info");
		struct.add(DWORD, "weak_bind_size", "size of weak binding info");
		struct.add(DWORD, "lazy_bind_off", "file offset to lazy binding info");
		struct.add(DWORD, "lazy_bind_size", "size of lazy binding info");
		struct.add(DWORD, "export_off", "file offset to lazy binding info");
		struct.add(DWORD, "export_size", "size of lazy binding info");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public void markup(Program program, MachHeader header, String source, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		markupRebaseInfo(program, header, source, monitor, log);
		markupBindInfo(program, header, source, monitor, log);
		markupWeakBindInfo(program, header, source, monitor, log);
		markupLazyBindInfo(program, header, source, monitor, log);
		markupExportInfo(program, header, source, monitor, log);

	}

	private void markupRebaseInfo(Program program, MachHeader header, String source,
			TaskMonitor monitor, MessageLog log) {
		markupPlateComment(program, fileOffsetToAddress(program, header, rebaseOff, rebaseSize),
			source, "rebase");
	}

	private void markupBindInfo(Program program, MachHeader header, String source,
			TaskMonitor monitor, MessageLog log) {
		markupPlateComment(program, fileOffsetToAddress(program, header, bindOff, bindSize),
			source, "bind");
	}

	private void markupWeakBindInfo(Program program, MachHeader header, String source,
			TaskMonitor monitor, MessageLog log) {
		markupPlateComment(program, fileOffsetToAddress(program, header, weakBindOff, weakBindSize),
			source, "weak bind");
	}

	private void markupLazyBindInfo(Program program, MachHeader header, String source,
			TaskMonitor monitor, MessageLog log) {
		markupPlateComment(program, fileOffsetToAddress(program, header, lazyBindOff, lazyBindSize),
			source, "lazy bind");
	}

	private void markupExportInfo(Program program, MachHeader header, String source,
			TaskMonitor monitor, MessageLog log) {
		markupPlateComment(program, fileOffsetToAddress(program, header, exportOff, exportSize),
			source, "export");
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			if (rebaseSize > 0) {
				Address start = baseAddress.getNewAddress(rebaseOff);
				api.createFragment(parentModule, getCommandName() + "_REBASE", start,
					rebaseSize);
			}
			if (bindSize > 0) {
				Address start = baseAddress.getNewAddress(bindOff);
				api.createFragment(parentModule, getCommandName() + "_BIND", start, bindSize);
			}
			if (weakBindSize > 0) {
				Address start = baseAddress.getNewAddress(weakBindOff);
				api.createFragment(parentModule, getCommandName() + "_WEAK_BIND", start,
					weakBindSize);
			}
			if (lazyBindSize > 0) {
				Address start = baseAddress.getNewAddress(lazyBindOff);
				api.createFragment(parentModule, getCommandName() + "_LAZY_BIND", start,
					lazyBindSize);
			}
			if (exportSize > 0) {
				Address start = baseAddress.getNewAddress(exportOff);
				api.createFragment(parentModule, getCommandName() + "_EXPORT", start,
					exportSize);
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
		}
	}
}
