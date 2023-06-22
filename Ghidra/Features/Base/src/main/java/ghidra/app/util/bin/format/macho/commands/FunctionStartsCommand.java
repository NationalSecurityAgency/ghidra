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
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a LC_FUNCTION_STARTS command. 
 */
public class FunctionStartsCommand extends LinkEditDataCommand {
	
	private List<LEB128Info> lebs = new ArrayList<>();

	/**
	 * Creates and parses a new {@link FunctionStartsCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	FunctionStartsCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader, dataReader);

		int i = 0;
		while (true) {
			LEB128Info info = dataReader.readNext(LEB128Info::unsigned);
			if (i + info.getLength() > datasize || info.asLong() == 0) {
				break;
			}
			i += info.getLength();
			lebs.add(info);
		}
	}

	/**
	 * Finds the {@link List} of function start addresses
	 * 
	 * @param textSegmentAddr The {@link Address} of the function starts' __TEXT segment
	 * @return The {@link List} of function start addresses
	 * @throws IOException if there was an issue reading bytes
	 */
	public List<Address> findFunctionStartAddrs(Address textSegmentAddr) throws IOException {
		List<Address> addrs = new ArrayList<>();
		long currentFuncOffset = 0;
		for (LEB128Info leb : lebs) {
			currentFuncOffset += leb.asLong();
			addrs.add(textSegmentAddr.add(currentFuncOffset));
		}
		return addrs;
	}

	@Override
	public void markup(Program program, MachHeader header, Address addr, String source,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (addr == null || datasize == 0) {
			return;
		}

		super.markup(program, header, addr, source, monitor, log);
		
		SegmentCommand textSegment = header.getSegment(SegmentNames.SEG_TEXT);
		if (textSegment == null) {
			return;
		}

		try {
			ReferenceManager referenceManager = program.getReferenceManager();
			Address textSegmentAddr = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(textSegment.getVMaddress());
			long currentFuncOffset = 0;
			for (LEB128Info leb : lebs) {
				Data d = DataUtilities.createData(program, addr, ULEB128, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(leb.getLength());
				currentFuncOffset += leb.asLong();
				Reference ref = referenceManager.addMemoryReference(d.getMinAddress(),
					textSegmentAddr.add(currentFuncOffset),
					RefType.DATA, SourceType.IMPORTED, 0);
				referenceManager.setPrimary(ref, true);
			}

		}
		catch (Exception e) {
			log.appendMsg(DyldChainedFixupsCommand.class.getSimpleName(), "Failed to markup %s."
					.formatted(LoadCommandTypes.getLoadCommandName(getCommandType())));
		}
	}
}
