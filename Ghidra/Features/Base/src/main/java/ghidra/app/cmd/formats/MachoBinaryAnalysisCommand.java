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
package ghidra.app.cmd.formats;

import java.util.List;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.LoadCommand;
import ghidra.app.util.bin.format.macho.commands.UnsupportedLoadCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MachoBinaryAnalysisCommand extends FlatProgramAPI
		implements BinaryAnalysisCommand, AnalysisWorker {

	private MessageLog messages = new MessageLog();
	private Address address;
	private boolean isRelativeToAddress;
	private ProgramModule module;

	public MachoBinaryAnalysisCommand() {
		super();
	}

	public MachoBinaryAnalysisCommand(Address address, ProgramModule module) {
		this(address, true, module);
	}

	public MachoBinaryAnalysisCommand(Address address, boolean isRelativeToAddress,
			ProgramModule module) {
		super();
		this.address = address;
		this.isRelativeToAddress = isRelativeToAddress;
		this.module = module;
	}

	@Override
	public boolean canApply(Program program) {
		try {
			if (!BinaryLoader.BINARY_NAME.equals(program.getExecutableFormat())) {
				return false;
			}
			Memory memory = program.getMemory();
			Address address = getAddress(program);
			int magic = memory.getInt(address);
			return MachConstants.isMagic(magic);
		}
		catch (Exception e) {
		}
		return false;
	}

	private Address getAddress(Program program) {
		return address == null ? program.getAddressFactory().getDefaultAddressSpace().getAddress(0)
				: address;
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception, CancelledException {

		BookmarkManager bookmarkManager = program.getBookmarkManager();

		ByteProvider provider =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);

		try {
			MachHeader header =
				new MachHeader(provider, getAddress(program).getOffset(), isRelativeToAddress);
			header.parse();

			Address machAddress = getAddress(program);
			DataType headerDT = header.toDataType();
			createData(machAddress, headerDT);
			setHeaderComment(header, machAddress);

			int commandStartIndex = headerDT.getLength();
			Address commandAddress = machAddress.add(commandStartIndex);

			createFragment(module, headerDT.getDisplayName(), machAddress, commandStartIndex);

			List<LoadCommand> commands = header.getLoadCommands();
			for (LoadCommand command : commands) {
				command.markupRawBinary(header, this, getAddress(program), module, monitor,
					messages);
				commandAddress = commandAddress.add(command.getCommandSize());
				if (command instanceof UnsupportedLoadCommand) {
					bookmarkManager.setBookmark(machAddress.add(command.getStartIndex()),
						BookmarkType.WARNING, "Load commands", command.getCommandName());
				}
			}

			return true;
		}
		catch (MachException e) {
			messages.appendMsg("Not a binary Mach-O program: Mach header not found.");
			return false;
		}
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) throws Exception {
		set(program, monitor);

		if (module == null) {
			module = program.getListing().getDefaultRootModule();
		}

		// Modify program and prevent events from triggering follow-on analysis
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
		return aam.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public String getName() {
		return "Mach-O Header Annotation";
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	private void setHeaderComment(MachHeader header, Address machAddress) {
		StringBuffer comments = new StringBuffer();
		comments.append("File type: ");
		comments.append(MachHeaderFileTypes.getFileTypeName(header.getFileType()));
		comments.append('\n');
		comments.append('\t');
		comments.append(MachHeaderFileTypes.getFileTypeDescription(header.getFileType()));
		comments.append('\n');
		comments.append('\n');
		comments.append("Flags:");
		List<String> flags = MachHeaderFlags.getFlags(header.getFlags());
		for (String flag : flags) {
			comments.append('\t');
			comments.append(flag);
			comments.append('\n');
		}
		setPlateComment(machAddress, comments.toString());
	}
}
