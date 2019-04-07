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
 * Represents a routines_command and routines_command_64 structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class RoutinesCommand extends LoadCommand {
    private long init_address;
	private long init_module;
	private long reserved1;
	private long reserved2;
	private long reserved3;
	private long reserved4;
	private long reserved5;
	private long reserved6;

	private boolean is32bit;

	static RoutinesCommand createRoutinesCommand(FactoryBundledWithBinaryReader reader,
			boolean is32bit) throws IOException {
        RoutinesCommand command = (RoutinesCommand) reader.getFactory().create(RoutinesCommand.class);
        command.initRoutinesCommand(reader, is32bit);
        return command;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public RoutinesCommand() {}

	private void initRoutinesCommand(FactoryBundledWithBinaryReader reader, boolean is32bit)
			throws IOException {
		initLoadCommand(reader);
		this.is32bit = is32bit;
		if (is32bit) {
			init_address = reader.readNextInt() & 0xffffffffL;
			init_module  = reader.readNextInt() & 0xffffffffL;
			reserved1    = reader.readNextInt() & 0xffffffffL;
			reserved2    = reader.readNextInt() & 0xffffffffL;
			reserved3    = reader.readNextInt() & 0xffffffffL;
			reserved4    = reader.readNextInt() & 0xffffffffL;
			reserved5    = reader.readNextInt() & 0xffffffffL;
			reserved6    = reader.readNextInt() & 0xffffffffL;
		}
		else {
			init_address = reader.readNextLong();
			init_module  = reader.readNextLong();
			reserved1    = reader.readNextLong();
			reserved2    = reader.readNextLong();
			reserved3    = reader.readNextLong();
			reserved4    = reader.readNextLong();
			reserved5    = reader.readNextLong();
			reserved6    = reader.readNextLong();			
		}
	}

	/**
	 * Address of initialization routine.
	 * @return address of initialization routine
	 */
	public long getInitializationRoutineAddress() {
		return init_address;
	}
	/**
	 * Index into the module table that the init routine is defined in.
	 * @return index into the module table that the init routine is defined in
	 */
	public long getInitializationRoutineModuleIndex() {
		return init_module;
	}
	public long getReserved1() {
		return reserved1;
	}
	public long getReserved2() {
		return reserved2;
	}
	public long getReserved3() {
		return reserved3;
	}
	public long getReserved4() {
		return reserved4;
	}
	public long getReserved5() {
		return reserved5;
	}
	public long getReserved6() {
		return reserved6;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
	    StructureDataType struct = new StructureDataType(getCommandName(), 0);
	    struct.add(DWORD, "cmd", null);
	    struct.add(DWORD, "cmdsize", null);
	    if (is32bit) {
		    struct.add(DWORD, "init_address", null);
		    struct.add(DWORD, "init_module", null);
		    struct.add(DWORD, "reserved1", null);
		    struct.add(DWORD, "reserved2", null);
		    struct.add(DWORD, "reserved3", null);
		    struct.add(DWORD, "reserved4", null);
		    struct.add(DWORD, "reserved5", null);
		    struct.add(DWORD, "reserved6", null);
	    }
	    else {
		    struct.add(QWORD, "init_address", null);
		    struct.add(QWORD, "init_module", null);
		    struct.add(QWORD, "reserved1", null);
		    struct.add(QWORD, "reserved2", null);
		    struct.add(QWORD, "reserved3", null);
		    struct.add(QWORD, "reserved4", null);
		    struct.add(QWORD, "reserved5", null);
		    struct.add(QWORD, "reserved6", null);
	    }
	    struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
	    return struct;
	}

	@Override
	public String getCommandName() {
		return "routines_command";
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary, ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				createFragment(api, baseAddress, parentModule);
				Address addr = baseAddress.getNewAddress(getStartIndex());
				api.createData(addr, toDataType());
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create "+getCommandName()+" - "+e.getMessage());
		}
	}
}
