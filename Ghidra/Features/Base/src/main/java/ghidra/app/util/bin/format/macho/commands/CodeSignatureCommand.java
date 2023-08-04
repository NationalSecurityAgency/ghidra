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
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureBlobParser;
import ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureGenericBlob;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a LC_CODE_SIGNATURE command. 
 */
public class CodeSignatureCommand extends LinkEditDataCommand {

	private CodeSignatureGenericBlob blob;

	/**
	 * Creates and parses a new {@link CodeSignatureCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	CodeSignatureCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader, dataReader);
		dataReader.setLittleEndian(false); // Everything that follows is always big-endian
		blob = CodeSignatureBlobParser.parse(dataReader);
	}

	@Override
	public void markup(Program program, MachHeader header, String source, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Address addr = fileOffsetToAddress(program, header, dataoff, datasize);
		if (addr == null) {
			return;
		}
		super.markup(program, header, source, monitor, log);

		try {
			Data d = DataUtilities.createData(program, addr, blob.toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			LoadCommand.setEndian(d, true);
			blob.markup(program, addr, header, monitor, log);
		}
		catch (Exception e) {
			log.appendMsg(CodeSignatureCommand.class.getSimpleName(),
				"Failed to markup: " + getContextualName(source, null));
		}
	}
}
