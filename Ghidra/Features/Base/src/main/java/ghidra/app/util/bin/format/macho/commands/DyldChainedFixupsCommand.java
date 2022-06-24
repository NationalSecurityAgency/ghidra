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
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_chained_fixups_command structure
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
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
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		try {
			if (isBinary) {
				super.markup(header, api, baseAddress, isBinary, parentModule, monitor, log);

				List<Address> addrs =
					api.getCurrentProgram().getMemory().locateAddressesForFileOffset(
						getDataOffset());
				if (addrs.size() <= 0) {
					throw new Exception("Chain Header does not exist in program");
				}
				Address dyldChainedHeader = addrs.get(0);

				markupChainedFixupHeader(header, api, dyldChainedHeader, parentModule, monitor);
			}
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

		Address segsAddr = baseAddress.add(chainHeader.getStarts_offset());

		DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();
		int[] seg_info_offset = chainedStartsInImage.getSeg_info_offset();

		DyldChainedStartsInSegment[] chainedStarts = chainedStartsInImage.getChainedStarts();
		for (int i = 0; i < chainedStarts.length; i++) {
			DyldChainedStartsInSegment startsInSeg = chainedStarts[i];
			DataType dataType = startsInSeg.toDataType();

			api.createData(segsAddr.add(seg_info_offset[i]), dataType);
		}
	}

	public DyldChainedFixupHeader getChainHeader() {
		return chainHeader;
	}
}
