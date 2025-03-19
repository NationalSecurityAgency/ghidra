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
 * Represents a linkedit_data_command structure 
 */
public class LinkEditDataCommand extends LoadCommand {
	protected long dataoff;
	protected long datasize;
	protected BinaryReader dataReader;

	/**
	 * Creates and parses a new {@link LinkEditDataCommand}.  Sets <code>dataReader</code> to the
	 * data offset.
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	LinkEditDataCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader);
		this.dataoff = loadCommandReader.readNextUnsignedInt();
		this.datasize = loadCommandReader.readNextUnsignedInt();
		this.dataReader = dataReader;
		this.dataReader.setPointerIndex(dataoff);
	}

	@Override
	public long getLinkerDataOffset() {
		return dataoff;
	}

	@Override
	public long getLinkerDataSize() {
		return datasize;
	}

	@Override
	public String getCommandName() {
		return "linkedit_data_command";
	}

	@Override
	public void markup(Program program, MachHeader header, String source, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		markupPlateComment(program, fileOffsetToAddress(program, header, dataoff, datasize), source,
			null);
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			if (datasize > 0) {
				Address start = baseAddress.getNewAddress(dataoff);
				api.createFragment(parentModule,
					LoadCommandTypes.getLoadCommandName(getCommandType()), start, datasize);
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
		struct.add(DWORD, "dataoff", null);
		struct.add(DWORD, "datasize", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

}
