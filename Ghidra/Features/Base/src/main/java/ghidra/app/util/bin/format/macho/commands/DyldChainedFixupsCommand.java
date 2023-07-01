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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.chained.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a <code>dyld_chained_fixups_command</code> structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedFixupsCommand extends LinkEditDataCommand {

	private DyldChainedFixupHeader chainHeader;

	/**
	 * Creates and parses a new {@link DyldChainedFixupsCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	DyldChainedFixupsCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader, dataReader);

		chainHeader = new DyldChainedFixupHeader(dataReader);
	}

	@Override
	public String getCommandName() {
		return "dyld_chained_fixups_command";
	}

	@Override
	public void markup(Program program, MachHeader header, Address addr, String source,
			TaskMonitor monitor, MessageLog log) throws CancelledException {

		if (addr == null || datasize == 0) {
			return;
		}

		super.markup(program, header, addr, source, monitor, log);

		try {
			DataUtilities.createData(program, addr, chainHeader.toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			Address segsAddr = addr.add(chainHeader.getStartsOffset());
			DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();
			DataUtilities.createData(program, segsAddr, chainedStartsInImage.toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			int[] segInfoOffset = chainedStartsInImage.getSegInfoOffset();
			List<DyldChainedStartsInSegment> chainedStarts =
				chainedStartsInImage.getChainedStarts();
			int skipCount = 0;
			for (int i = 0; i < segInfoOffset.length; i++) {
				if (segInfoOffset[i] == 0) {
					// The chainStarts list doesn't have entries for 0 offsets, so we must keep
					// track of the index differences between the 2 entities
					skipCount++;
					continue;
				}
				DyldChainedStartsInSegment startsInSeg = chainedStarts.get(i - skipCount);
				if (startsInSeg != null) {
					DataUtilities.createData(program, segsAddr.add(segInfoOffset[i]),
						startsInSeg.toDataType(), -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
			}
		}
		catch (Exception e) {
			log.appendMsg(DyldChainedFixupsCommand.class.getSimpleName(), "Failed to markup %s."
					.formatted(LoadCommandTypes.getLoadCommandName(getCommandType())));
		}
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			List<Address> addrs = api.getCurrentProgram()
					.getMemory()
					.locateAddressesForFileOffset(getLinkerDataOffset());
			if (addrs.size() <= 0) {
				throw new Exception("Chain Header does not exist in program");
			}
			Address dyldChainedHeader = addrs.get(0);

			markupChainedFixupHeader(header, api, dyldChainedHeader, parentModule, monitor);
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
			log.appendException(e);
		}
	}

	private void markupChainedFixupHeader(MachHeader header, FlatProgramAPI api,
			Address baseAddress, ProgramModule parentModule, TaskMonitor monitor)
			throws DuplicateNameException, IOException, CodeUnitInsertionException, Exception {
		DataType cHeader = chainHeader.toDataType();
		api.createData(baseAddress, cHeader);

		Address segsAddr = baseAddress.add(chainHeader.getStartsOffset());

		DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();
		int[] segInfoOffset = chainedStartsInImage.getSegInfoOffset();

		List<DyldChainedStartsInSegment> chainedStarts = chainedStartsInImage.getChainedStarts();
		for (int i = 0; i < chainedStarts.size(); i++) {
			DyldChainedStartsInSegment startsInSeg = chainedStarts.get(i);
			DataType dataType = startsInSeg.toDataType();

			api.createData(segsAddr.add(segInfoOffset[i]), dataType);
		}
	}

	public DyldChainedFixupHeader getChainHeader() {
		return chainHeader;
	}
}
