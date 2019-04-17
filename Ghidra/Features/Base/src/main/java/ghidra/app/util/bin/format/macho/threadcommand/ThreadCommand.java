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
package ghidra.app.util.bin.format.macho.threadcommand;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.LoadCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a thread_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class ThreadCommand extends LoadCommand {
	private ThreadStateHeader threadStateHeader;
	private ThreadState threadState;

	public static ThreadCommand createThreadCommand(FactoryBundledWithBinaryReader reader,
			MachHeader header) throws IOException {
		ThreadCommand threadCommand =
			(ThreadCommand) reader.getFactory().create(ThreadCommand.class);
		threadCommand.initThreadCommand(reader, header);
		return threadCommand;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ThreadCommand() {
	}

	private void initThreadCommand(FactoryBundledWithBinaryReader reader, MachHeader header)
			throws IOException {
		initLoadCommand(reader);

		threadStateHeader = ThreadStateHeader.createThreadStateHeader(reader);

		if (header.getCpuType() == CpuTypes.CPU_TYPE_X86) {
			if (threadStateHeader.getFlavor() == ThreadStateX86.x86_THREAD_STATE32) {
				threadState = ThreadStateX86_32.createThreadStateX86_32(reader);
			}
		}
		else if (header.getCpuType() == CpuTypes.CPU_TYPE_X86_64) {
			if (threadStateHeader.getFlavor() == ThreadStateX86.x86_THREAD_STATE64) {
				threadState = ThreadStateX86_64.createThreadStateX86_64(reader);
			}
		}
		else if (header.getCpuType() == CpuTypes.CPU_TYPE_POWERPC) {
			if (threadStateHeader.getFlavor() == ThreadStatePPC.PPC_THREAD_STATE) {
				threadState = ThreadStatePPC.createThreadStatePPC(reader, header.is32bit());
			}
		}
		else if (header.getCpuType() == CpuTypes.CPU_TYPE_POWERPC64) {
			if (threadStateHeader.getFlavor() == ThreadStatePPC.PPC_THREAD_STATE64) {
				threadState = ThreadStatePPC.createThreadStatePPC(reader, header.is32bit());
			}
		}
		else if (header.getCpuType() == CpuTypes.CPU_TYPE_ARM) {
			if (threadStateHeader.getFlavor() == ThreadStateARM.ARM_THREAD_STATE) {
				threadState = ThreadStateARM.createThreadStateARM(reader);
			}
		}
		else if (header.getCpuType() == CpuTypes.CPU_TYPE_ARM_64) {
			if (threadStateHeader.getFlavor() == ThreadStateARM_64.ARM64_THREAD_STATE) {
				threadState = ThreadStateARM_64.createThreadStateARM_64(reader);
			}	
		}
		else {
			Msg.info("Mach-O Thread Command",
				"Unsupported thread command flavor: 0x" +
					Integer.toHexString(threadStateHeader.getFlavor()) + " for CPU type 0x" +
					Integer.toHexString(header.getCpuType()));
			//throw new MachException("Unsupported thread command flavor: 0x"+Integer.toHexString(threadStateHeader.getFlavor())+" for CPU type 0x"+Integer.toHexString(header.getCpuType()));
		}
	}

	public ThreadStateHeader getThreadStateHeader() {
		return threadStateHeader;
	}

	public ThreadState getThreadState() {
		return threadState;
	}

	public long getInitialInstructionPointer() {
		if (threadState != null) {
			return threadState.getInstructionPointer();
		}
		return -1;//TODO
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.add(threadStateHeader.toDataType(), "threadStateHeader", null);
		struct.add(threadState.toDataType(), "threadState", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	@Override
	public String getCommandName() {
		return "thread_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address addr = baseAddress.getNewAddress(getStartIndex());
				api.createData(addr, toDataType());
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
		}
	}
}
