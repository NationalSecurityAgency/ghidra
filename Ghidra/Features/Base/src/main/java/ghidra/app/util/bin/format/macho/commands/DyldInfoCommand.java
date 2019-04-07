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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_info_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class DyldInfoCommand extends LoadCommand {
	private int rebase_off;
	private int rebase_size;
	private int bind_off;
	private int bind_size;
	private int weak_bind_off;
	private int weak_bind_size;
	private int lazy_bind_off;
	private int lazy_bind_size;
	private int export_off;
	private int export_size;

	static DyldInfoCommand createDyldInfoCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {
		DyldInfoCommand command =
			(DyldInfoCommand) reader.getFactory().create(DyldInfoCommand.class);
		command.initDyldInfoCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DyldInfoCommand() {
	}

	private void initDyldInfoCommand(FactoryBundledWithBinaryReader reader) throws IOException {
		initLoadCommand(reader);

		rebase_off = reader.readNextInt();
		rebase_size = reader.readNextInt();
		bind_off = reader.readNextInt();
		bind_size = reader.readNextInt();
		weak_bind_off = reader.readNextInt();
		weak_bind_size = reader.readNextInt();
		lazy_bind_off = reader.readNextInt();
		lazy_bind_size = reader.readNextInt();
		export_off = reader.readNextInt();
		export_size = reader.readNextInt();
	}

	@Override
	public String getCommandName() {
		return "dyld_info_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address address = baseAddress.getNewAddress(getStartIndex());
				api.createData(address, toDataType());

				if (rebase_size > 0) {
					Address start = baseAddress.getNewAddress(rebase_off);
					api.createFragment(parentModule, getCommandName() + "_REBASE", start,
						rebase_size);
				}
				if (bind_size > 0) {
					Address start = baseAddress.getNewAddress(bind_off);
					api.createFragment(parentModule, getCommandName() + "_BIND", start, bind_size);
				}
				if (weak_bind_size > 0) {
					Address start = baseAddress.getNewAddress(weak_bind_off);
					api.createFragment(parentModule, getCommandName() + "_WEAK_BIND", start,
						weak_bind_size);
				}
				if (lazy_bind_size > 0) {
					Address start = baseAddress.getNewAddress(lazy_bind_off);
					api.createFragment(parentModule, getCommandName() + "_LAZY_BIND", start,
						lazy_bind_size);
				}
				if (export_size > 0) {
					Address start = baseAddress.getNewAddress(export_off);
					api.createFragment(parentModule, getCommandName() + "_EXPORT", start,
						export_size);
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(DWORD, "rebase_off", null);
		struct.add(DWORD, "rebase_size", null);
		struct.add(DWORD, "bind_off", null);
		struct.add(DWORD, "bind_size", null);
		struct.add(DWORD, "weak_bind_off", null);
		struct.add(DWORD, "weak_bind_size", null);
		struct.add(DWORD, "lazy_bind_off", null);
		struct.add(DWORD, "lazy_bind_size", null);
		struct.add(DWORD, "export_off", null);
		struct.add(DWORD, "export_size", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	/**
	 * file offset to rebase info
	 * @return file offset to rebase info
	 */
	public int getRebaseOffset() {
		return rebase_off;
	}

	/**
	 * size of rebase info
	 * @return size of rebase info
	 */
	public int getRebaseSize() {
		return rebase_size;
	}

	/**
	 * file offset to binding info
	 * @return file offset to binding info
	 */
	public int getBindOffset() {
		return bind_off;
	}

	/**
	 * size of binding info
	 * @return size of binding info
	 */
	public int getBindSize() {
		return bind_size;
	}

	/**
	 * file offset to weak binding info
	 * @return file offset to weak binding info
	 */
	public int getWeakBindOffset() {
		return weak_bind_off;
	}

	/**
	 * size of weak binding info
	 * @return size of weak binding info
	 */
	public int getWeakBindSize() {
		return weak_bind_size;
	}

	/**
	 * file offset to lazy binding info
	 * @return file offset to lazy binding info
	 */
	public int getLazyBindOffset() {
		return lazy_bind_off;
	}

	/**
	 * size of lazy binding infs
	 * @return
	 */
	public int getLazyBindSize() {
		return lazy_bind_size;
	}

	/**
	 * 
	 * @return
	 */
	public int getExportOffset() {
		return export_off;
	}

	/**
	 * 
	 * @return
	 */
	public int getExportSize() {
		return export_size;
	}
}
