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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a LC_DATA_IN_CODE command. 
 */
public class DataInCodeCommand extends LinkEditDataCommand {

	private List<DataInCodeEntry> entries = new ArrayList<>();

	/**
	 * Creates and parses a new {@link DataInCodeCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	DataInCodeCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader, dataReader);

		for (int i = 0; i + DataInCodeEntry.SIZE <= datasize; i += DataInCodeEntry.SIZE) {
			entries.add(new DataInCodeEntry(dataReader));
		}
	}

	/**
	 * Gets the {@link List} of {@link DataInCodeEntry}s
	 * 
	 * @return The {@link List} of {@link DataInCodeEntry}s
	 */
	public List<DataInCodeEntry> getEntries() {
		return entries;
	}

	@Override
	public void markup(Program program, MachHeader header, Address addr, String source,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (addr == null || datasize == 0) {
			return;
		}

		super.markup(program, header, addr, source, monitor, log);

		try {
			for (DataInCodeEntry entry : entries) {
				DataUtilities.createData(program, addr, entry.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(DataInCodeEntry.SIZE);
			}
		}
		catch (Exception e) {
			log.appendMsg(DyldChainedFixupsCommand.class.getSimpleName(), "Failed to markup %s."
					.formatted(LoadCommandTypes.getLoadCommandName(getCommandType())));
		}
	}
}
